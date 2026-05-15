#pragma once

#include <windows.h>

#include <cstdint>
#include <filesystem>
#include <map>
#include <string>
#include <vector>

enum class ScanObjectType : std::uint32_t
{
    Unknown = 0,
    PeFile = 1,
    PowerShellScript = 2
};

struct AvDatabaseInfo
{
    bool loaded = false;
    std::wstring releaseDateUtc;
    std::uint32_t recordCount = 0;
};

struct ScanMatch
{
    std::wstring path;
    std::wstring objectType;
    std::wstring threatName;
    std::uint64_t offset = 0;
};

struct ScanResult
{
    bool success = true;
    bool malicious = false;
    std::uint64_t scannedObjects = 0;
    std::uint64_t infectedObjects = 0;
    std::wstring summary;
    std::wstring details;
    std::vector<ScanMatch> matches;
};

class IByteStream
{
public:
    virtual ~IByteStream() = default;

    virtual std::uint64_t Size() const = 0;
    virtual bool Read(std::uint64_t offset, std::uint8_t* buffer, std::size_t bytesToRead) const = 0;
};

class AntivirusDatabase
{
public:
    bool LoadBuiltIn();
    void Clear();

    [[nodiscard]] bool IsLoaded() const noexcept;
    [[nodiscard]] AvDatabaseInfo GetInfo() const;

    [[nodiscard]] ScanResult ScanStream(
        const IByteStream& stream,
        ScanObjectType objectType,
        const std::wstring& displayPath) const;

    [[nodiscard]] ScanResult ScanFile(const std::filesystem::path& filePath) const;
    [[nodiscard]] ScanResult ScanDirectory(const std::filesystem::path& directoryPath) const;
    [[nodiscard]] ScanResult ScanFixedDrives() const;

private:
    struct AvRecord
    {
        std::wstring threatName;
        std::uint64_t objectSignaturePrefix = 0;
        std::uint32_t objectSignatureLength = 0;
        std::vector<std::uint8_t> objectSignature;
        std::uint64_t offsetBegin = 0;
        std::uint64_t offsetEnd = 0;
        ScanObjectType objectType = ScanObjectType::Unknown;
        std::vector<std::uint8_t> avRecordSignature;
    };

    using RecordTree = std::map<std::uint64_t, std::vector<AvRecord>>;

    static std::wstring ObjectTypeToDisplayName(ScanObjectType objectType);
    static ScanObjectType DetectObjectType(const std::filesystem::path& path);
    static ScanResult MergeResults(ScanResult aggregate, const ScanResult& next);

    static std::vector<std::uint8_t> ComputeSha256(const std::vector<std::uint8_t>& bytes);
    static std::vector<std::uint8_t> SerializeRecordForSignature(const AvRecord& record);
    static bool VerifyRecordSignature(const AvRecord& record);
    static std::uint64_t PrefixFromBytes(const std::uint8_t* bytes);
    static std::wstring BuildDetails(const std::vector<ScanMatch>& matches);
    static std::wstring BuildSummary(
        bool malicious,
        std::uint64_t scannedObjects,
        std::uint64_t infectedObjects);

    bool AddRecord(
        const std::wstring& threatName,
        const std::vector<std::uint8_t>& plainSignature,
        std::uint64_t offsetBegin,
        std::uint64_t offsetEnd,
        ScanObjectType objectType);

    bool loaded_ = false;
    AvDatabaseInfo info_{};
    RecordTree records_;
};
