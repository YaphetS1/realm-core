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

#include <realm/object-store/shared_realm.hpp>

namespace realm {
class TableView;
class Obj;
struct ColKey;
struct VersionID;
class SyncUser;
class AuditObjectSerializer;
namespace util {
class Logger;
}

struct AuditConfig {
    std::shared_ptr<SyncUser> audit_user;
    std::string partition_value_prefix = "audit-";
    std::vector<std::pair<std::string, std::string>> metadata;
    std::shared_ptr<AuditObjectSerializer> serializer;
    std::shared_ptr<util::Logger> logger;
};

class AuditInterface {
public:
    virtual ~AuditInterface() = default;

    virtual void record_query(VersionID, const TableView&) = 0;
    virtual void record_read(VersionID, const Obj& obj, const Obj& parent, ColKey col) = 0;
    virtual void record_write(VersionID old_version, VersionID new_version) = 0;
};

std::shared_ptr<AuditInterface> make_audit_context(Realm::Config const& parent_config,
                                                   AuditConfig const& audit_config);
} // namespace realm
