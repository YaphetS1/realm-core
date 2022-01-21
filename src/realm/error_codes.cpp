/*************************************************************************
 *
 * Copyright 2021 Realm Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 **************************************************************************/

#include "realm/error_codes.hpp"
#include <iostream>

namespace realm {

namespace {
// You can think of this namespace as a compile-time map<ErrorCodes::Error, ErrorExtraInfoParser*>.
namespace parsers {
} // namespace parsers
} // namespace


template <>
bool ErrorCodes::is_a<ErrorCategory::generic_error>(ErrorCodes::Error error)
{
    switch (error) {
        case UnknownError:
        case RuntimeError:
        case LogicError:
        case InvalidArgument:
            return true;
        default:
            break;
    }
    return false;
}

template <>
bool ErrorCodes::is_a<ErrorCategory::logic_error>(ErrorCodes::Error error)
{
    switch (error) {
        case SerializationError:
        case SyntaxError:
            return true;
        default:
            break;
    }
    return false;
}

template <>
bool ErrorCodes::is_a<ErrorCategory::runtime_error>(ErrorCodes::Error error)
{
    switch (error) {
        case OutOfDiskSpace:
        case InvalidQuery:
            return true;
        default:
            break;
    }
    return false;
}

template <>
bool ErrorCodes::is_a<ErrorCategory::invalid_argument>(ErrorCodes::Error error)
{
    switch (error) {
        case InvalidPath:
        case InvalidQueryArg:
            return true;
        default:
            break;
    }
    return false;
}

std::string_view ErrorCodes::error_string(Error code)
{
    static_assert(sizeof(Error) == sizeof(int));

    switch (code) {
        case OK:
            return "OK";
        case UnknownError:
            return "UnknownError";
        case RuntimeError:
            return "RuntimeError";
        case LogicError:
            return "LogicError";
        case BrokenPromise:
            return "BrokenPromise";
        case InvalidArgument:
            return "InvalidArgument";
        case OutOfMemory:
            return "OutOfMemory";
        case NoSuchTable:
            return "NoSuchTable";
        case CrossTableLinkTarget:
            return "CrossTableLinkTarget";
        case UnsupportedFileFormatVersion:
            return "UnsupportedFileFormatVersion";
        case MultipleSyncAgents:
            return "MultipleSyncAgents";
        case AddressSpaceExhausted:
            return "AddressSpaceExhausted";
        case OutOfDiskSpace:
            return "OutOfDiskSpace";
        case KeyNotFound:
            return "KeyNotFound";
        case OutOfBounds:
            return "OutOfBounds";
        case IllegalOperation:
            return "IllegalOperation";
        case KeyAlreadyUsed:
            return "KeyAlreadyUsed";
        case SerializationError:
            return "SerializationError";
        case InvalidPath:
            return "InvalidPath";
        case DuplicatePrimaryKeyValue:
            return "DuplicatePrimaryKeyValue";
        case SyntaxError:
            return "SyntaxError";
        case InvalidQueryArg:
            return "InvalidQueryArg";
        case InvalidQuery:
            return "InvalidQuery";
        case NotInATransaction:
            return "NotInATransaction";
        case WrongThread:
            return "WrongThread";
        case InvalidatedObject:
            return "InvalidatedObject";
        case InvalidProperty:
            return "InvalidProperty";
        case MissingPrimaryKey:
            return "MissingPrimaryKey";
        case UnexpectedPrimaryKey:
            return "UnexpectedPrimaryKey";
        case WrongPrimaryKeyType:
            return "WrongPrimaryKeyType";
        case ModifyPrimaryKey:
            return "ModifyPrimaryKey";
        case ReadOnlyProperty:
            return "ReadOnlyProperty";
        case PropertyNotNullable:
            return "PropertyNotNullable";
        case MaximumFileSizeExceeded:
            return "MaximumFileSizeExceeded";
        case TableNameInUse:
            return "TableNameInUse";
        case InvalidTableRef:
            return "InvalidTableRef";
        case BadChangeset:
            return "BadChangeset";
        case InvalidDictionaryKey:
            return "InvalidDictionaryKey";
        case InvalidDictionaryValue:
            return "InvalidDictionaryValue";
        default:
            return "UnknownError";
    }
}

ErrorCodes::Error ErrorCodes::from_string(std::string_view name)
{
    if (name == std::string_view("OK"))
        return OK;
    if (name == std::string_view("UnknownError"))
        return UnknownError;
    if (name == std::string_view("RuntimeError"))
        return RuntimeError;
    if (name == std::string_view("LogicError"))
        return LogicError;
    if (name == std::string_view("BrokenPromise"))
        return BrokenPromise;
    if (name == std::string_view("InvalidArgument"))
        return InvalidArgument;
    if (name == std::string_view("OutOfMemory"))
        return OutOfMemory;
    if (name == std::string_view("NoSuchTable"))
        return NoSuchTable;
    if (name == std::string_view("CrossTableLinkTarget"))
        return CrossTableLinkTarget;
    if (name == std::string_view("UnsupportedFileFormatVersion"))
        return UnsupportedFileFormatVersion;
    if (name == std::string_view("MultipleSyncAgents"))
        return MultipleSyncAgents;
    if (name == std::string_view("AddressSpaceExhausted"))
        return AddressSpaceExhausted;
    if (name == std::string_view("OutOfDiskSpace"))
        return OutOfDiskSpace;
    if (name == std::string_view("KeyNotFound"))
        return KeyNotFound;
    if (name == std::string_view("OutOfBounds"))
        return OutOfBounds;
    if (name == std::string_view("IllegalOperation"))
        return IllegalOperation;
    if (name == std::string_view("KeyAlreadyUsed"))
        return KeyAlreadyUsed;
    if (name == std::string_view("SerializationError"))
        return SerializationError;
    if (name == std::string_view("InvalidPath"))
        return InvalidPath;
    if (name == std::string_view("DuplicatePrimaryKeyValue"))
        return DuplicatePrimaryKeyValue;
    if (name == std::string_view("SyntaxError"))
        return SyntaxError;
    if (name == std::string_view("InvalidQueryArg"))
        return InvalidQueryArg;
    if (name == std::string_view("InvalidQuery"))
        return InvalidQuery;
    if (name == std::string_view("NotInATransaction"))
        return NotInATransaction;
    if (name == std::string_view("WrongThread"))
        return WrongThread;
    if (name == std::string_view("InvalidatedObject"))
        return InvalidatedObject;
    if (name == std::string_view("InvalidProperty"))
        return InvalidProperty;
    if (name == std::string_view("MissingPrimaryKey"))
        return MissingPrimaryKey;
    if (name == std::string_view("UnexpectedPrimaryKey"))
        return UnexpectedPrimaryKey;
    if (name == std::string_view("WrongPrimaryKeyType"))
        return WrongPrimaryKeyType;
    if (name == std::string_view("ModifyPrimaryKey"))
        return ModifyPrimaryKey;
    if (name == std::string_view("ReadOnlyProperty"))
        return ReadOnlyProperty;
    if (name == std::string_view("PropertyNotNullable"))
        return PropertyNotNullable;
    if (name == std::string_view("MaximumFileSizeExceeded"))
        return MaximumFileSizeExceeded;
    if (name == std::string_view("TableNameInUse"))
        return TableNameInUse;
    if (name == std::string_view("InvalidTableRef"))
        return InvalidTableRef;
    if (name == std::string_view("BadChangeset"))
        return BadChangeset;
    if (name == std::string_view("InvalidDictionaryKey"))
        return InvalidDictionaryKey;
    if (name == std::string_view("InvalidDictionaryValue"))
        return InvalidDictionaryValue;
    return UnknownError;
}

std::ostream& operator<<(std::ostream& stream, ErrorCodes::Error code)
{
    return stream << ErrorCodes::error_string(code);
}

} // namespace realm
