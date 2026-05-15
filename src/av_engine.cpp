#include "av_engine.h"

#include <bcrypt.h>

#include <algorithm>
#include <array>
#include <fstream>
#include <iomanip>
#include <limits>
#include <sstream>

#pragma comment(lib, "Bcrypt.lib")

namespace
{
constexpr wchar_t kRecordSignatureSalt[] = L"PracticaAvRecordSignature";
constexpr std::uint32_t kSha256Length = 32;
constexpr std::size_t kPrefixLength = 8;

class FileByteStream final : public IByteStream
{
public:
    explicit FileByteStream(const std::filesystem::path& filePath)
    {
        stream_.open(filePath, std::ios::binary);
        if (!stream_)
        {
            return;
        }

        stream_.seekg(0, std::ios::end);
        const auto endPosition = stream_.tellg();
        if (endPosition < 0)
        {
            size_ = 0;
            return;
        }

        size_ = static_cast<std::uint64_t>(endPosition);
    }

    [[nodiscard]] bool IsOpen() const noexcept
    {
        return stream_.is_open() && stream_.good();
    }

    std::uint64_t Size() const override
    {
        return size_;
    }

    bool Read(const std::uint64_t offset, std::uint8_t* buffer, const std::size_t bytesToRead) const override
    {
        if (!IsOpen() || !buffer)
        {
            return false;
        }

        if (offset > size_ || bytesToRead > size_ - offset)
        {
            return false;
        }

        stream_.clear();
        stream_.seekg(static_cast<std::streamoff>(offset), std::ios::beg);
        stream_.read(reinterpret_cast<char*>(buffer), static_cast<std::streamsize>(bytesToRead));
        return stream_.good();
    }

private:
    mutable std::ifstream stream_{};
    std::uint64_t size_ = 0;
};

std::vector<std::uint8_t> ToBytes(const std::wstring& value)
{
    const auto* begin = reinterpret_cast<const std::uint8_t*>(value.data());
    const auto* end = begin + (value.size() * sizeof(wchar_t));
    return {begin, end};
}

void AppendUint32(std::vector<std::uint8_t>& bytes, const std::uint32_t value)
{
    for (unsigned int i = 0; i < sizeof(value); ++i)
    {
        bytes.push_back(static_cast<std::uint8_t>((value >> (i * 8U)) & 0xFFU));
    }
}

void AppendUint64(std::vector<std::uint8_t>& bytes, const std::uint64_t value)
{
    for (unsigned int i = 0; i < sizeof(value); ++i)
    {
        bytes.push_back(static_cast<std::uint8_t>((value >> (i * 8U)) & 0xFFU));
    }
}

void AppendBytes(std::vector<std::uint8_t>& target, const std::vector<std::uint8_t>& source)
{
    target.insert(target.end(), source.begin(), source.end());
}

ScanResult BuildFailureResult(const std::wstring& summary)
{
    ScanResult result{};
    result.success = false;
    result.summary = summary;
    result.details = summary;
    return result;
}
} // namespace

bool AntivirusDatabase::LoadBuiltIn()
{
    Clear();

    info_.loaded = true;
    info_.releaseDateUtc = L"2026-05-15T00:00:00Z";

    bool ok = true;
    ok = ok && AddRecord(
        L"Demo.PE.Injector",
        std::vector<std::uint8_t>{'M', 'Z', 'P', 'R', 'A', 'C', 'T', 'I', 'C', 'A', '-', 'M', 'A', 'L', '-', 'P', 'E'},
        0,
        4096,
        ScanObjectType::PeFile);
    ok = ok && AddRecord(
        L"Demo.PE.Dropper",
        std::vector<std::uint8_t>{'M', 'Z', 'P', 'R', 'A', 'C', 'T', '2', 'D', 'R', 'O', 'P', 'P', 'E', 'R'},
        0,
        8192,
        ScanObjectType::PeFile);
    ok = ok && AddRecord(
        L"Demo.PS.Downloader",
        std::vector<std::uint8_t>{'W', 'r', 'i', 't', 'e', '-', 'H', 'o', 's', 't', ' ', '"', 'P', 'R', 'A', 'C', 'T', 'I', 'C', 'A', '-', 'M', 'A', 'L', '-', 'P', 'S', '"'},
        0,
        std::numeric_limits<std::uint64_t>::max(),
        ScanObjectType::PowerShellScript);
    ok = ok && AddRecord(
        L"Demo.PS.Obfuscated",
        std::vector<std::uint8_t>{'S', 't', 'a', 'r', 't', '-', 'B', 'i', 't', 's', 'T', 'r', 'a', 'n', 's', 'f', 'e', 'r', ' ', '"', 'P', 'R', 'A', 'C', 'T', 'I', 'C', 'A', '-', 'P', 'S', '2', '"'},
        0,
        std::numeric_limits<std::uint64_t>::max(),
        ScanObjectType::PowerShellScript);

    loaded_ = ok;
    info_.loaded = ok;
    info_.recordCount = ok ? static_cast<std::uint32_t>(4) : 0;
    if (!ok)
    {
        Clear();
    }

    return ok;
}

void AntivirusDatabase::Clear()
{
    records_.clear();
    loaded_ = false;
    info_ = {};
}

bool AntivirusDatabase::IsLoaded() const noexcept
{
    return loaded_;
}

AvDatabaseInfo AntivirusDatabase::GetInfo() const
{
    return info_;
}

ScanResult AntivirusDatabase::ScanStream(
    const IByteStream& stream,
    const ScanObjectType objectType,
    const std::wstring& displayPath) const
{
    if (!loaded_)
    {
        return BuildFailureResult(L"Антивирусные базы не загружены.");
    }

    ScanResult result{};
    result.scannedObjects = 1;

    const std::uint64_t size = stream.Size();
    if (size < kPrefixLength)
    {
        result.summary = BuildSummary(false, 1, 0);
        result.details = L"Подходящих сигнатур не найдено.";
        return result;
    }

    std::array<std::uint8_t, kPrefixLength> prefixBytes{};
    for (std::uint64_t position = 0; position + kPrefixLength <= size; ++position)
    {
        if (!stream.Read(position, prefixBytes.data(), prefixBytes.size()))
        {
            return BuildFailureResult(L"Не удалось прочитать поток для сканирования.");
        }

        const std::uint64_t prefix = PrefixFromBytes(prefixBytes.data());
        const auto treeIt = records_.find(prefix);
        if (treeIt == records_.end())
        {
            continue;
        }

        for (const AvRecord& record : treeIt->second)
        {
            if (record.objectType != objectType)
            {
                continue;
            }

            if (position < record.offsetBegin || position > record.offsetEnd)
            {
                continue;
            }

            if (record.objectSignatureLength < kPrefixLength)
            {
                continue;
            }

            const std::size_t remainingBytes = static_cast<std::size_t>(record.objectSignatureLength - kPrefixLength);
            if (position + record.objectSignatureLength > size)
            {
                continue;
            }

            std::vector<std::uint8_t> signatureCandidate(prefixBytes.begin(), prefixBytes.end());
            if (remainingBytes > 0)
            {
                std::vector<std::uint8_t> extraBytes(remainingBytes);
                if (!stream.Read(position + kPrefixLength, extraBytes.data(), extraBytes.size()))
                {
                    continue;
                }

                signatureCandidate.insert(signatureCandidate.end(), extraBytes.begin(), extraBytes.end());
            }

            if (ComputeSha256(signatureCandidate) != record.objectSignature)
            {
                continue;
            }

            result.malicious = true;
            result.infectedObjects = 1;
            result.matches.push_back({
                displayPath,
                ObjectTypeToDisplayName(objectType),
                record.threatName,
                position});
            result.summary = BuildSummary(true, 1, 1);
            result.details = BuildDetails(result.matches);
            return result;
        }
    }

    result.summary = BuildSummary(false, 1, 0);
    result.details = L"Подходящих сигнатур не найдено.";
    return result;
}

ScanResult AntivirusDatabase::ScanFile(const std::filesystem::path& filePath) const
{
    if (!std::filesystem::exists(filePath))
    {
        return BuildFailureResult(L"Файл не найден.");
    }

    const ScanObjectType objectType = DetectObjectType(filePath);
    if (objectType == ScanObjectType::Unknown)
    {
        ScanResult result{};
        result.scannedObjects = 1;
        result.summary = L"Файл пропущен: неподдерживаемый тип объекта.";
        result.details = result.summary;
        return result;
    }

    FileByteStream stream(filePath);
    if (!stream.IsOpen())
    {
        return BuildFailureResult(L"Не удалось открыть файл для сканирования.");
    }

    return ScanStream(stream, objectType, filePath.wstring());
}

ScanResult AntivirusDatabase::ScanDirectory(const std::filesystem::path& directoryPath) const
{
    if (!std::filesystem::exists(directoryPath) || !std::filesystem::is_directory(directoryPath))
    {
        return BuildFailureResult(L"Каталог не найден.");
    }

    ScanResult aggregate{};
    for (const auto& entry : std::filesystem::recursive_directory_iterator(directoryPath, std::filesystem::directory_options::skip_permission_denied))
    {
        if (!entry.is_regular_file())
        {
            continue;
        }

        const ScanObjectType objectType = DetectObjectType(entry.path());
        if (objectType == ScanObjectType::Unknown)
        {
            continue;
        }

        aggregate = MergeResults(std::move(aggregate), ScanFile(entry.path()));
    }

    if (aggregate.summary.empty())
    {
        aggregate.summary = BuildSummary(false, 0, 0);
        aggregate.details = L"Поддерживаемые файлы в каталоге не найдены.";
    }

    return aggregate;
}

ScanResult AntivirusDatabase::ScanFixedDrives() const
{
    DWORD drivesMask = GetLogicalDrives();
    if (drivesMask == 0)
    {
        return BuildFailureResult(L"Не удалось получить список логических дисков.");
    }

    ScanResult aggregate{};
    for (wchar_t driveLetter = L'A'; driveLetter <= L'Z'; ++driveLetter)
    {
        const DWORD bit = 1UL << (driveLetter - L'A');
        if ((drivesMask & bit) == 0)
        {
            continue;
        }

        wchar_t rootPath[] = {driveLetter, L':', L'\\', L'\0'};
        if (GetDriveTypeW(rootPath) != DRIVE_FIXED)
        {
            continue;
        }

        aggregate = MergeResults(std::move(aggregate), ScanDirectory(rootPath));
    }

    if (aggregate.summary.empty())
    {
        aggregate.summary = BuildSummary(false, 0, 0);
        aggregate.details = L"Поддерживаемые файлы на несъёмных дисках не найдены.";
    }

    return aggregate;
}

std::wstring AntivirusDatabase::ObjectTypeToDisplayName(const ScanObjectType objectType)
{
    switch (objectType)
    {
    case ScanObjectType::PeFile:
        return L"PE";
    case ScanObjectType::PowerShellScript:
        return L"PowerShell";
    default:
        return L"Unknown";
    }
}

ScanObjectType AntivirusDatabase::DetectObjectType(const std::filesystem::path& path)
{
    const std::wstring extension = path.extension().wstring();
    if (_wcsicmp(extension.c_str(), L".exe") == 0 ||
        _wcsicmp(extension.c_str(), L".dll") == 0 ||
        _wcsicmp(extension.c_str(), L".sys") == 0)
    {
        return ScanObjectType::PeFile;
    }

    if (_wcsicmp(extension.c_str(), L".ps1") == 0)
    {
        return ScanObjectType::PowerShellScript;
    }

    return ScanObjectType::Unknown;
}

ScanResult AntivirusDatabase::MergeResults(ScanResult aggregate, const ScanResult& next)
{
    aggregate.success = aggregate.success && next.success;
    aggregate.malicious = aggregate.malicious || next.malicious;
    aggregate.scannedObjects += next.scannedObjects;
    aggregate.infectedObjects += next.infectedObjects;
    aggregate.matches.insert(aggregate.matches.end(), next.matches.begin(), next.matches.end());
    aggregate.summary = BuildSummary(aggregate.malicious, aggregate.scannedObjects, aggregate.infectedObjects);
    aggregate.details = aggregate.matches.empty()
        ? (aggregate.scannedObjects == 0 ? L"Результаты сканирования отсутствуют." : L"Вредоносные объекты не обнаружены.")
        : BuildDetails(aggregate.matches);
    return aggregate;
}

std::vector<std::uint8_t> AntivirusDatabase::ComputeSha256(const std::vector<std::uint8_t>& bytes)
{
    BCRYPT_ALG_HANDLE algorithm = nullptr;
    BCRYPT_HASH_HANDLE hash = nullptr;
    DWORD objectLength = 0;
    DWORD bytesCopied = 0;
    std::vector<std::uint8_t> objectBuffer;
    std::vector<std::uint8_t> digest(kSha256Length);

    if (BCryptOpenAlgorithmProvider(&algorithm, BCRYPT_SHA256_ALGORITHM, nullptr, 0) < 0)
    {
        return {};
    }

    if (BCryptGetProperty(algorithm, BCRYPT_OBJECT_LENGTH, reinterpret_cast<PUCHAR>(&objectLength), sizeof(objectLength), &bytesCopied, 0) < 0)
    {
        BCryptCloseAlgorithmProvider(algorithm, 0);
        return {};
    }

    objectBuffer.resize(objectLength);
    if (BCryptCreateHash(algorithm, &hash, objectBuffer.data(), objectLength, nullptr, 0, 0) < 0)
    {
        BCryptCloseAlgorithmProvider(algorithm, 0);
        return {};
    }

    if (!bytes.empty() &&
        BCryptHashData(hash, const_cast<PUCHAR>(reinterpret_cast<const UCHAR*>(bytes.data())), static_cast<ULONG>(bytes.size()), 0) < 0)
    {
        BCryptDestroyHash(hash);
        BCryptCloseAlgorithmProvider(algorithm, 0);
        return {};
    }

    if (BCryptFinishHash(hash, digest.data(), static_cast<ULONG>(digest.size()), 0) < 0)
    {
        BCryptDestroyHash(hash);
        BCryptCloseAlgorithmProvider(algorithm, 0);
        return {};
    }

    BCryptDestroyHash(hash);
    BCryptCloseAlgorithmProvider(algorithm, 0);
    return digest;
}

std::vector<std::uint8_t> AntivirusDatabase::SerializeRecordForSignature(const AvRecord& record)
{
    std::vector<std::uint8_t> bytes = ToBytes(record.threatName);
    AppendUint64(bytes, record.objectSignaturePrefix);
    AppendUint32(bytes, record.objectSignatureLength);
    AppendBytes(bytes, record.objectSignature);
    AppendUint64(bytes, record.offsetBegin);
    AppendUint64(bytes, record.offsetEnd);
    AppendUint32(bytes, static_cast<std::uint32_t>(record.objectType));

    const std::vector<std::uint8_t> salt = ToBytes(kRecordSignatureSalt);
    AppendBytes(bytes, salt);
    return bytes;
}

bool AntivirusDatabase::VerifyRecordSignature(const AvRecord& record)
{
    return ComputeSha256(SerializeRecordForSignature(record)) == record.avRecordSignature;
}

std::uint64_t AntivirusDatabase::PrefixFromBytes(const std::uint8_t* bytes)
{
    std::uint64_t prefix = 0;
    for (std::size_t i = 0; i < kPrefixLength; ++i)
    {
        prefix |= (static_cast<std::uint64_t>(bytes[i]) << (i * 8U));
    }
    return prefix;
}

std::wstring AntivirusDatabase::BuildDetails(const std::vector<ScanMatch>& matches)
{
    if (matches.empty())
    {
        return L"Вредоносные объекты не обнаружены.";
    }

    std::wstringstream stream;
    for (const auto& match : matches)
    {
        stream << L"[" << match.objectType << L"] "
               << match.path
               << L" | сигнатура: " << match.threatName
               << L" | смещение: " << match.offset
               << L"\r\n";
    }

    return stream.str();
}

std::wstring AntivirusDatabase::BuildSummary(
    const bool malicious,
    const std::uint64_t scannedObjects,
    const std::uint64_t infectedObjects)
{
    std::wstringstream stream;
    stream << L"Просканировано объектов: " << scannedObjects
           << L", заражено: " << infectedObjects
           << L". Статус: " << (malicious ? L"обнаружены угрозы" : L"угроз не найдено");
    return stream.str();
}

bool AntivirusDatabase::AddRecord(
    const std::wstring& threatName,
    const std::vector<std::uint8_t>& plainSignature,
    const std::uint64_t offsetBegin,
    const std::uint64_t offsetEnd,
    const ScanObjectType objectType)
{
    if (plainSignature.size() < kPrefixLength || plainSignature.size() > std::numeric_limits<std::uint32_t>::max())
    {
        return false;
    }

    AvRecord record{};
    record.threatName = threatName;
    record.objectSignaturePrefix = PrefixFromBytes(plainSignature.data());
    record.objectSignatureLength = static_cast<std::uint32_t>(plainSignature.size());
    record.objectSignature = ComputeSha256(plainSignature);
    record.offsetBegin = offsetBegin;
    record.offsetEnd = offsetEnd;
    record.objectType = objectType;
    record.avRecordSignature = ComputeSha256(SerializeRecordForSignature(record));

    if (record.objectSignature.size() != kSha256Length || !VerifyRecordSignature(record))
    {
        return false;
    }

    records_[record.objectSignaturePrefix].push_back(std::move(record));
    return true;
}
