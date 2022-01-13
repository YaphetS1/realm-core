////////////////////////////////////////////////////////////////////////////
//
// Copyright 2022 Realm Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
////////////////////////////////////////////////////////////////////////////

#include <realm/object-store/audit.hpp>
#include <realm/object-store/audit_serializer.hpp>

#include <realm/object-store/impl/collection_change_builder.hpp>
#include <realm/object-store/impl/collection_notifier.hpp>
#include <realm/object-store/impl/realm_coordinator.hpp>
#include <realm/object-store/object_schema.hpp>
#include <realm/object-store/object_store.hpp>
#include <realm/object-store/property.hpp>
#include <realm/object-store/schema.hpp>
#include <realm/object-store/sync/sync_manager.hpp>
#include <realm/object-store/sync/sync_user.hpp>

#include <realm/table_view.hpp>
#include <realm/util/file.hpp>
#include <realm/util/logger.hpp>

#include <external/json/json.hpp>
#include <external/mpark/variant.hpp>
#include <compression.h>
#include <dispatch/dispatch.h>
#include <sys/time.h>

using namespace realm;

namespace realm {
static void to_json(nlohmann::json& j, Timestamp const& ts) noexcept
{
    if (ts.is_null()) {
        j = nullptr;
        return;
    }

    time_t seconds = ts.get_seconds();
    char buf[sizeof "1970-01-01T00:00:00.123Z"];
    size_t len = strftime(buf, sizeof buf, "%FT%T", gmtime(&seconds));
    snprintf(buf + len, sizeof ".000Z", ".%03dZ", ts.get_nanoseconds() / 1'000'000);
    j = buf;
}
static void to_json(nlohmann::json& j, StringData s) noexcept
{
    if (s)
        j = std::string(s);
    else
        j = nullptr;
}
} // namespace realm

namespace {

namespace audit_event {
struct Query {
    Timestamp timestamp;
    realm::VersionID version;
    TableKey table;
    std::vector<ObjKey> objects;
};
struct Write {
    Timestamp timestamp;
    VersionID prev_version;
    VersionID version;
};
struct Object {
    Timestamp timestamp;
    realm::VersionID version;
    TableKey table;
    ObjKey obj;
    TableKey parent_table;
    ObjKey parent_obj;
    ColKey parent_col;
};
struct Custom {
    Timestamp timestamp;
    std::string activity;
    util::Optional<std::string> event_type;
    util::Optional<std::string> data;
    bool compress;
};
} // namespace audit_event

using Event = mpark::variant<audit_event::Query, audit_event::Write, audit_event::Object, audit_event::Custom>;

Timestamp now()
{
    struct timeval tv;
    gettimeofday(&tv, nullptr);
    return Timestamp(tv.tv_sec, tv.tv_usec * 1000);
}

class TransactLogHandler {
public:
    TransactLogHandler(Group const& g, AuditObjectSerializer& serializer)
        : m_group(g)
        , m_serializer(serializer)
        , m_data(nlohmann::json::object())
    {
    }

    std::string const& data() const
    {
        return m_str;
    }

    void parse_complete()
    {
        for (auto& [table_key, builder] : m_info.tables) {
            if (builder.empty()) {
                continue;
            }
            auto table = m_group.get_table(table_key);
            auto object_type = ObjectStore::object_type_for_table_name(table->get_name());
            auto& data = m_data[object_type];
            auto& modifications = builder.get_modifications();
            if (!modifications.empty()) {
                auto& objects = data["modifications"];
                for (auto& [obj_key, columns] : modifications) {
                    auto& obj = objects[objects.size()];
                    m_serializer.to_json(obj["oldValue"], table->get_object(obj_key));
                }
            }
            auto& deletions = builder.get_deletions();
            if (!deletions.empty()) {
                auto& objects = data["deletions"];
                for (auto& obj_key : deletions) {
                    m_serializer.to_json(objects[objects.size()], table->get_object(obj_key));
                }
            }
        }
    }

    void after_advance()
    {
        for (auto& [table_key, builder] : m_info.tables) {
            if (builder.empty()) {
                continue;
            }
            auto table = m_group.get_table(table_key);
            auto& data = m_data[ObjectStore::object_type_for_table_name(table->get_name())];
            auto& modifications = builder.get_modifications();
            if (!modifications.empty()) {
                auto& objects = data["modifications"];
                size_t i = 0;
                for (auto& [obj_key, columns] : modifications) {
                    auto& obj = objects[i++];
                    auto& newValue = obj["newValue"];
                    m_serializer.to_json(newValue, table->get_object(obj_key));

                    // Remove all fields from newValue which did not actually change
                    auto& oldValue = obj["oldValue"];
                    for (auto it = oldValue.begin(); it != oldValue.end(); ++it) {
                        if (newValue[it.key()] == it.value())
                            newValue.erase(it.key());
                    }
                }
            }

            auto& insertions = builder.get_insertions();
            if (!insertions.empty()) {
                auto& objects = data["insertions"];
                for (auto& obj_key : insertions) {
                    m_serializer.to_json(objects[objects.size()], table->get_object(obj_key));
                }
            }
        }
        m_str = m_data.dump();
    }

    bool select_table(TableKey tk) noexcept
    {
        m_active_table = &m_info.tables[tk];
        return true;
    }

    bool create_object(ObjKey k) noexcept
    {
        REALM_ASSERT(m_active_table);
        m_active_table->insertions_add(k);
        return true;
    }

    bool remove_object(ObjKey k) noexcept
    {
        REALM_ASSERT(m_active_table);
        m_active_table->deletions_add(k);
        return true;
    }

    bool modify_object(ColKey col, ObjKey obj) noexcept
    {
        REALM_ASSERT(m_active_table);
        m_active_table->modifications_add(obj, col);
        return true;
    }

    bool select_collection(ColKey col, ObjKey obj) noexcept
    {
        REALM_ASSERT(m_active_table);
        m_active_table->modifications_add(obj, col);
        return true;
    }

    // clang-format off
    // We don't care about fine-grained changes to collections and just do
    // object-level change tracking, which is covered by select_collection()
    bool list_set(size_t) { return true; }
    bool list_insert(size_t) { return true; }
    bool list_move(size_t, size_t) { return true; }
    bool list_erase(size_t) { return true; }
    bool list_clear(size_t) { return true; }
    bool dictionary_insert(size_t, Mixed const&) { return true; }
    bool dictionary_set(size_t, Mixed const&) { return true; }
    bool dictionary_erase(size_t, Mixed const&) { return true; }
    bool set_insert(size_t) { return true; }
    bool set_erase(size_t) { return true; }
    bool set_clear(size_t) { return true; }

    // We don't run this code on arbitrary transactions that could perform schema changes
    bool insert_group_level_table(TableKey) { unexpected_instruction(); }
    bool erase_class(TableKey) { unexpected_instruction(); }
    bool rename_class(TableKey) { unexpected_instruction(); }
    bool enumerate_string_column(ColKey) { unexpected_instruction(); }
    bool insert_column(ColKey) { unexpected_instruction(); }
    bool erase_column(ColKey) { unexpected_instruction(); }
    bool rename_column(ColKey) { unexpected_instruction(); }
    bool set_link_type(ColKey) { unexpected_instruction(); }
    bool typed_link_change(ColKey, TableKey) { unexpected_instruction(); }
    // clang-format on

private:
    REALM_NORETURN
    REALM_NOINLINE
    void unexpected_instruction()
    {
        REALM_TERMINATE("Unexpected transaction log instruction encountered");
    }

    Group const& m_group;
    AuditObjectSerializer& m_serializer;
    _impl::TransactionChangeInfo m_info;
    ObjectChangeSet* m_active_table = nullptr;
    nlohmann::json m_data;
    std::string m_str;
};

class ReadCombiner {
public:
    bool operator()(audit_event::Query& query)
    {
        if (m_previous_query && m_previous_query->table == query.table &&
            m_previous_query->version == query.version) {
            m_previous_query->objects.insert(m_previous_query->objects.end(), query.objects.begin(),
                                             query.objects.end());
            return true;
        }
        m_previous_query = &query;
        return false;
    }

    bool operator()(audit_event::Object const& obj)
    {
        if (m_previous_query && m_previous_query->table == obj.table && m_previous_query->version == obj.version) {
            m_previous_query->objects.push_back(obj.obj);
            return true;
        }
        if (m_previous_obj && m_previous_obj->obj == obj.obj && m_previous_obj->version == obj.version) {
            return true;
        }
        m_previous_obj = &obj;
        return false;
    }

    bool operator()(audit_event::Write const&)
    {
        return false;
    }
    bool operator()(audit_event::Custom const&)
    {
        return false;
    }

private:
    const audit_event::Object* m_previous_obj = nullptr;
    audit_event::Query* m_previous_query = nullptr;
};

class EmptyQueryFilter {
public:
    EmptyQueryFilter(DB& db)
        : m_db(db)
    {
    }

    bool operator()(audit_event::Query& query)
    {
        query.objects.erase(std::remove_if(query.objects.begin(), query.objects.end(),
                                           [&](auto& obj) {
                                               return !object_exists(query.version, query.table, obj);
                                           }),
                            query.objects.end());
        return query.objects.empty();
    }

    bool operator()(audit_event::Object const& obj)
    {
        return !object_exists(obj.version, obj.table, obj.obj);
    }

    bool operator()(audit_event::Write const&)
    {
        return false;
    }
    bool operator()(audit_event::Custom const&)
    {
        return false;
    }

private:
    DB& m_db;
    TransactionRef m_transaction;

    bool object_exists(VersionID v, TableKey table, ObjKey obj)
    {
        if (!m_transaction || m_transaction->get_version_of_current_transaction() != v) {
            m_transaction = m_db.start_read(v);
        }
        return m_transaction->get_table(table)->is_valid(obj);
    }
};

class TrackLinkAccesses {
public:
    TrackLinkAccesses(AuditObjectSerializer& serializer)
        : m_serializer(serializer)
    {
    }

    void operator()(audit_event::Object const& obj)
    {
        if (obj.parent_table) {
            m_serializer.link_accessed(obj.version, obj.parent_table, obj.parent_obj, obj.parent_col);
        }
    }

    void operator()(audit_event::Query&) {}
    void operator()(audit_event::Write const&) {}
    void operator()(audit_event::Custom const&) {}

private:
    AuditObjectSerializer& m_serializer;
};

struct MetadataSchema {
    std::vector<std::pair<std::string, std::string>> metadata;
    std::vector<ColKey> metadata_cols;
    ColKey col_timestamp;
    ColKey col_activity;
    ColKey col_event_type;
    ColKey col_data;
};

class AuditEventWriter {
public:
    AuditEventWriter(DB& db, MetadataSchema const& metadata, StringData activity_name, Table& audit_table,
                     AuditObjectSerializer& serializer)
        : m_source_db(db)
        , m_schema(metadata)
        , m_activity(activity_name)
        , m_serializer(serializer)
        , m_table(audit_table)
    {
    }

    size_t operator()(audit_event::Query const& query)
    {
        auto& g = read(query.version);
        nlohmann::json data;
        auto table = g.get_table(query.table);
        data["type"] = ObjectStore::object_type_for_table_name(table->get_name());
        auto& value = data["value"];
        for (auto& obj : query.objects)
            m_serializer.to_json(value[value.size()], table->get_object(obj));
        auto str = data.dump();
        return write_event(query.timestamp, m_activity, "read", str);
    }

    size_t operator()(audit_event::Write const& write)
    {
        auto& g = read(write.prev_version);
        TransactLogHandler changes(g, m_serializer);
        g.advance_read(&changes, write.version);
        changes.after_advance();

        return write_event(write.timestamp, m_activity, "write", changes.data());
    }

    size_t operator()(audit_event::Object const& obj)
    {
        auto& g = read(obj.version);
        auto table = g.get_table(obj.table);

        if (obj.parent_table)
            m_serializer.link_accessed(obj.version, obj.parent_table, obj.parent_obj, obj.parent_col);

        nlohmann::json data;
        data["type"] = ObjectStore::object_type_for_table_name(table->get_name());
        m_serializer.to_json(data["value"][0], table->get_object(obj.obj));
        auto str = data.dump();
        return write_event(obj.timestamp, m_activity, "read", str);
    }

    size_t operator()(audit_event::Custom const& event)
    {
        return write_event(event.timestamp, event.activity, event.event_type, event.data, event.compress);
    }

private:
    DB& m_source_db;
    MetadataSchema const& m_schema;
    AuditObjectSerializer& m_serializer;
    Table& m_table;
    const StringData m_activity;

    TransactionRef m_source_transaction;

    std::vector<uint8_t> m_compress_buffer;
    std::vector<uint8_t> m_compress_scratch;

    Transaction& read(VersionID v)
    {
        if (!m_source_transaction || m_source_transaction->get_version_of_current_transaction() != v) {
            m_source_transaction = m_source_db.start_read(v);
            m_serializer.set_version(v);
        }
        return *m_source_transaction;
    }

    size_t write_event(Timestamp timestamp, StringData activity, StringData event_type, StringData data,
                       bool compress = true)
    {
        auto obj = m_table.create_object();
        obj.set(m_schema.col_timestamp, timestamp);
        obj.set(m_schema.col_activity, activity);
        if (event_type)
            obj.set(m_schema.col_event_type, event_type);
        if (data)
            obj.set(m_schema.col_data, compress ? compress_data(data) : BinaryData(data.data(), data.size()));
        size_t size = activity.size() + event_type.size();
        for (size_t i = 0; i < m_schema.metadata.size(); ++i) {
            size += m_schema.metadata[i].second.size();
            obj.set(m_schema.metadata_cols[i], m_schema.metadata[i].second);
        }
        return size + obj.get<BinaryData>(m_schema.col_data).size();
    }

    BinaryData compress_data(StringData data)
    {
        // The maximum size increase from DEFLATE is a 5-byte header for every
        // 16383 byte block, as it'll simply write the block uncompressed if
        // it would grow in size
        size_t max_size_required = data.size() + 5 * (data.size() / 16383 + 1);
        if (m_compress_buffer.size() < max_size_required)
            m_compress_buffer.resize(max_size_required);
        if (m_compress_scratch.empty())
            m_compress_scratch.resize(compression_encode_scratch_buffer_size(COMPRESSION_ZLIB));

        size_t size =
            compression_encode_buffer(&m_compress_buffer[0], m_compress_buffer.size(), (const uint8_t*)data.data(),
                                      data.size(), &m_compress_scratch[0], COMPRESSION_ZLIB);
        return BinaryData((char*)m_compress_buffer.data(), size);
    }
};

class AuditContext : public AuditInterface {
public:
    AuditContext(AuditConfig const& audit_config);
    ~AuditContext();

    void init(std::weak_ptr<AuditContext>, const AuditConfig& audit_config, Realm::Config const& parent_config);
    void update_metadata(std::vector<std::pair<std::string, std::string>>&& new_metadata);

    void begin_scope(std::string_view name);
    void end_scope(util::UniqueFunction<void(std::exception_ptr)>&& completion);
    void record_event(std::string_view activity, util::Optional<std::string> event_type,
                      util::Optional<std::string> data, bool compress,
                      util::UniqueFunction<void(std::exception_ptr)>&& completion);

    void record_query(VersionID, TableView const&) override;
    void record_write(VersionID, VersionID) override;
    void record_read(VersionID, const Obj& row, const Obj& parent, ColKey col) override;

    void close();

private:
    struct Scope {
        std::shared_ptr<MetadataSchema> metadata;
        std::string activity_name;
        std::vector<Event> events;
        std::shared_ptr<Transaction> source_transaction;
        util::UniqueFunction<void(std::exception_ptr)> completion;
    };

    std::weak_ptr<AuditContext> m_weak_self;
    std::shared_ptr<MetadataSchema> m_metadata;
    std::shared_ptr<DB> m_source_db;
    std::shared_ptr<DB> m_audit_db;
    std::shared_ptr<AuditObjectSerializer> m_serializer;
    std::shared_ptr<util::Logger> m_logger;

    std::mutex m_mutex;
    std::shared_ptr<Scope> m_current_scope;
    dispatch_queue_t m_queue;

    void pin_version(VersionID);
    void trigger_write(std::shared_ptr<Scope>);
    void handle_error(SyncError);
    void process_scope(AuditContext::Scope& scope) const;

    friend class AuditEventWriter;
};

AuditContext::AuditContext(AuditConfig const& audit_config)
    : m_metadata(std::make_shared<MetadataSchema>(MetadataSchema{audit_config.metadata}))
    , m_serializer(audit_config.serializer)
    , m_queue(dispatch_queue_create("Realm audit worker", DISPATCH_QUEUE_SERIAL_WITH_AUTORELEASE_POOL))
{
    if (!m_serializer) {
        m_serializer = std::make_shared<AuditObjectSerializer>();
    }
}

void AuditContext::init(std::weak_ptr<AuditContext> weak_self, const AuditConfig& audit_config,
                        Realm::Config const& parent_config)
{
    m_weak_self = weak_self;

    auto parent_sync_config = parent_config.sync_config.get();
    REALM_ASSERT(parent_sync_config);
    auto audit_user = audit_config.audit_user;
    if (!audit_user)
        audit_user = parent_sync_config->user;

    ObjectSchema schema;
    schema.name = "AuditEvent";
    schema.persisted_properties = {
        {"timestamp", PropertyType::Date},
        {"activity", PropertyType::String},
        {"eventType", PropertyType::String | PropertyType::Nullable},
        {"data", PropertyType::Data | PropertyType::Nullable},
    };
    for (auto& [key, _] : audit_config.metadata) {
        schema.persisted_properties.push_back({key, PropertyType::String | PropertyType::Nullable});
    }

    std::string partition = audit_config.partition_value_prefix + parent_sync_config->partition_value;
    auto sync_config = std::make_shared<SyncConfig>(audit_user, std::move(partition));
    sync_config->client_resync_mode = ClientResyncMode::Manual;
    sync_config->recovery_directory = std::string("io.realm.audit");
    sync_config->error_handler = [weak_self](std::shared_ptr<SyncSession> const&, SyncError error) {
        if (auto self = weak_self.lock())
            self->handle_error(error);
    };

    Realm::Config config;
    config.automatic_change_notifications = false;
    config.cache = false;
    config.schema_mode = SchemaMode::AdditiveExplicit;
    config.schema_version = 0;
    config.schema = Schema{schema};
    config.path = audit_user->sync_manager()->path_for_realm(*sync_config);
    config.sync_config = sync_config;
    config.should_compact_on_launch_function = [](uint64_t total_size, uint64_t used_space) {
        return total_size > 5'000'000 && used_space * 5 < total_size;
    };

    // We want to open the audit Realm synchronously so that we can report
    // errors if we fail to open it, but we need to open it on the queue so that
    // we block if we're currently handling a client reset error.
    std::exception_ptr e;
    dispatch_sync(m_queue, [&] {
        try {
            Realm::get_shared_realm(std::move(config));
        }
        catch (...) {
            e = std::current_exception();
        }
    });
    if (e)
        std::rethrow_exception(e);
}

void AuditContext::update_metadata(std::vector<std::pair<std::string, std::string>>&& new_metadata)
{
    std::lock_guard<std::mutex> lock(m_mutex);
    m_metadata = std::make_shared<MetadataSchema>(MetadataSchema{std::move(new_metadata)});
}

AuditContext::~AuditContext() = default;

void AuditContext::record_query(VersionID version, TableView const& tv)
{
    std::lock_guard<std::mutex> lock(m_mutex);
    if (!m_current_scope)
        return;
    if (tv.size() == 0)
        return; // Query didn't match any objects so there wasn't actually a read

    pin_version(version);
    std::vector<ObjKey> objects;
    for (size_t i = 0, count = tv.size(); i < count; ++i)
        objects.push_back(tv.get_key(i));

    m_current_scope->events.push_back(
        audit_event::Query{now(), version, tv.get_target_table()->get_key(), std::move(objects)});
}

void AuditContext::record_read(VersionID version, const Obj& obj, const Obj& parent, ColKey col)
{
    std::lock_guard<std::mutex> lock(m_mutex);
    if (!m_current_scope)
        return;
    pin_version(version);
    TableKey parent_table_key;
    ObjKey parent_obj_key;
    if (parent.is_valid()) {
        parent_table_key = parent.get_table()->get_key();
        parent_obj_key = parent.get_key();
    }
    m_current_scope->events.push_back(audit_event::Object{now(), version, obj.get_table()->get_key(), obj.get_key(),
                                                          parent_table_key, parent_obj_key, col});
}

void AuditContext::record_write(realm::VersionID old_version, realm::VersionID new_version)
{
    std::lock_guard<std::mutex> lock(m_mutex);
    if (!m_current_scope)
        return;
    pin_version(old_version);
    m_current_scope->events.push_back(audit_event::Write{now(), old_version, new_version});
}

void AuditContext::record_event(std::string_view activity, util::Optional<std::string> event_type,
                                util::Optional<std::string> data, bool compress,
                                util::UniqueFunction<void(std::exception_ptr)>&& completion)

{
    std::lock_guard<std::mutex> lock(m_mutex);
    auto scope = std::make_shared<Scope>(Scope{m_metadata, std::string(activity)});
    scope->events.push_back(audit_event::Custom{now(), std::string(activity), event_type, data, compress});
    scope->completion = std::move(completion);
    trigger_write(std::move(scope));
}

void AuditContext::pin_version(VersionID version)
{
    if (!m_current_scope->source_transaction ||
        m_current_scope->source_transaction->get_version_of_current_transaction() < version) {
        m_current_scope->source_transaction = m_source_db->start_read(version);
    }
}

void AuditContext::begin_scope(std::string_view name)
{
    std::lock_guard<std::mutex> lock(m_mutex);
    if (m_current_scope)
        throw std::logic_error("Cannot begin audit scope: audit already in progress");
    m_current_scope = std::make_shared<Scope>(Scope{m_metadata, std::string(name)});
}

void AuditContext::end_scope(util::UniqueFunction<void(std::exception_ptr)>&& completion)
{
    std::lock_guard<std::mutex> lock(m_mutex);
    if (!m_current_scope)
        throw std::logic_error("Cannot end audit scope: no audit in progress");
    m_current_scope->completion = std::move(completion);
    trigger_write(std::move(m_current_scope));
    m_current_scope = nullptr;
}

void AuditContext::process_scope(AuditContext::Scope& scope) const
{
    try {
        // Merge single object reads following a query into that query
        {
            ReadCombiner combiner;
            auto& events = scope.events;
            events.erase(std::remove_if(events.begin(), events.end(),
                                        [&](auto& event) {
                                            return mpark::visit(combiner, event);
                                        }),
                         events.end());
        }

        // Filter out OOB reads from newly-created objects and empty queries
        {
            EmptyQueryFilter filter{*m_source_db};
            auto& events = scope.events;
            events.erase(std::remove_if(events.begin(), events.end(),
                                        [&](auto& event) {
                                            return mpark::visit(filter, event);
                                        }),
                         events.end());
        }

        // Gather information about link accesses so that we can include
        // information about the linked object in the audit event for the parent
        {
            TrackLinkAccesses track{*m_serializer};
            auto& events = scope.events;
            for (size_t i = 0; i < events.size(); ++i) {
                m_serializer->set_event_index(i);
                mpark::visit(track, events[i]);
            }
            m_serializer->sort_link_accesses();
        }

        auto tr = m_audit_db->start_write();
        auto table = tr->get_table("class_AuditEvent");
        if (!scope.metadata->col_timestamp) {
            scope.metadata->col_timestamp = table->get_column_key("timestamp");
            scope.metadata->col_activity = table->get_column_key("activity");
            scope.metadata->col_event_type = table->get_column_key("eventType");
            scope.metadata->col_data = table->get_column_key("data");
            for (auto& [key, _] : scope.metadata->metadata) {
                if (auto col = table->get_column_key(key)) {
                    scope.metadata->metadata_cols.push_back(col);
                }
                else {
                    constexpr bool nullable = true;
                    scope.metadata->metadata_cols.push_back(table->add_column(type_String, key, nullable));
                }
            }
        }

        AuditEventWriter writer{*m_source_db, *scope.metadata, scope.activity_name, *table, *m_serializer};

        constexpr const size_t max_batch_size = 10'000;
        constexpr const size_t max_payload_size = 4 * 1024 * 1024;
        size_t payload_size = 0;
        size_t batch_size = 0;
        for (size_t i = 0; i < scope.events.size(); ++i) {
            m_serializer->set_event_index(i);
            payload_size += mpark::visit(writer, scope.events[i]);
            if (payload_size > max_payload_size || ++batch_size > max_batch_size) {
                {
                    DisableReplication dr(*tr);
                    table->clear();
                }
                tr->commit_and_continue_as_read();
                tr->promote_to_write();
                payload_size = 0;
                batch_size = 0;
            }
        }
        {
            DisableReplication dr(*tr);
            table->clear();
        }
        tr->commit();

        if (scope.completion)
            scope.completion(nullptr);
    }
    catch (std::exception const& e) {
        m_logger->error("Error when writing audit scope: %1", e.what());
        if (scope.completion)
            scope.completion(std::current_exception());
    }
    catch (...) {
        m_logger->error("Unknoqn error when writing audit scope");
        if (scope.completion)
            scope.completion(std::current_exception());
    }
    m_serializer->scope_complete();
}

void AuditContext::close()
{
    m_source_db = nullptr;
    m_audit_db = nullptr;
}

void AuditContext::trigger_write(std::shared_ptr<Scope> scope)
{
    dispatch_async(m_queue, [self = m_weak_self.lock(), scope = std::move(scope)]() {
        self->m_logger->info("Processing audit scope for '%1'", self->m_audit_db->get_path());
        self->process_scope(*scope);
    });
}

void AuditContext::handle_error(SyncError error)
{
    m_logger->error("Audit received sync error: %1 (ec=%2)", error.message, error.error_code.value());
    if (!error.is_client_reset_requested())
        return; // FIXME: forward somewhere?
}
} // anonymous namespace

std::shared_ptr<AuditInterface> make_audit_context(Realm::Config const& parent_config,
                                                   AuditConfig const& audit_config)
{
    auto context = std::make_shared<AuditContext>(audit_config);
    context->init(context, audit_config, parent_config);
    return context;
}

bool AuditObjectSerializer::get_field(nlohmann::json& field, const Obj& obj, ColKey col, Mixed const& value)
{
    switch (value.get_type()) {
        case type_Int:
            field = value.get<int64_t>();
            return true;
        case type_Bool:
            field = value.get<bool>();
            return true;
        case type_String:
            field = value.get<StringData>();
            return true;
        case type_Timestamp:
            field = value.get<Timestamp>();
            return true;
        case type_Double:
            field = value.get<Double>();
            return true;
        case type_Float:
            field = value.get<Float>();
            return true;
        case type_Link: {
            auto target = obj.get_target_table(col)->get_object(value.get<ObjKey>());
            if (accessed_link(m_version.version, obj, col)) {
                to_json(field, target);
                return true;
            }
            return get_field(field, obj, col, target.get_primary_key());
        }
        case type_TypedLink: {
            auto target = obj.get_table()->get_parent_group()->get_object(value.get<ObjLink>());
            if (accessed_link(m_version.version, obj, col)) {
                to_json(field, target);
                return true;
            }
            return get_field(field, obj, col, target.get_primary_key());
        }
        default:
            return false;
    }
}

bool AuditObjectSerializer::get_field(nlohmann::json& field, const Obj& obj, ColKey col)
{
    if (obj.is_null(col)) {
        field = nullptr;
        return true;
    }

    if (col.is_collection()) {
        field = nlohmann::json::array();
        auto collection = obj.get_collection_ptr(col);
        for (size_t i = 0, size = collection->size(); i < size; ++i) {
            get_field(field[i], obj, col, collection->get_any(i));
        }
        return true;
    }

    return get_field(field, obj, col, obj.get_any(col));
}

void AuditObjectSerializer::to_json(nlohmann::json& out, const Obj& obj)
{
    auto& table = *obj.get_table();
    for (auto col : table.get_column_keys()) {
        auto col_name = table.get_column_name(col);
        if (!get_field(out[col_name], obj, col))
            out.erase(col_name);
    }
}

void AuditObjectSerializer::link_accessed(VersionID version, TableKey table, ObjKey obj, ColKey col)
{
    m_accessed_links.push_back({version.version, table, obj, col, m_index});
}

void AuditObjectSerializer::sort_link_accesses() noexcept
{
    static constexpr const size_t max = -1;
    std::sort(m_accessed_links.begin(), m_accessed_links.end(), [](auto& a, auto& b) {
        return std::make_tuple(a.version, a.table, a.col, a.obj, max - a.event_ndx) <
               std::make_tuple(b.version, b.table, b.col, b.obj, max - b.event_ndx);
    });
    m_accessed_links.erase(std::unique(m_accessed_links.begin(), m_accessed_links.end(),
                                       [](auto& a, auto& b) {
                                           return std::make_tuple(a.version, a.table, a.col, a.obj) ==
                                                  std::make_tuple(b.version, b.table, b.col, b.obj);
                                       }),
                           m_accessed_links.end());
}

bool AuditObjectSerializer::accessed_link(uint_fast64_t version, const Obj& obj, ColKey col) const noexcept
{
    auto cmp = [](auto& a, auto& b) {
        return std::make_tuple(a.version, a.table, a.col, a.obj) < std::make_tuple(b.version, b.table, b.col, b.obj);
    };
    auto link = LinkAccess{version, obj.get_table()->get_key(), obj.get_key(), col, 0};
    auto it = std::lower_bound(m_accessed_links.begin(), m_accessed_links.end(), link, cmp);
    return it != m_accessed_links.end() && !cmp(link, *it) && it->event_ndx > m_index;
}
