#pragma comment(lib, "user32.lib")
#pragma comment(lib, "gdi32.lib")
#pragma comment(lib, "psapi.lib")
#pragma comment(lib, "wintrust.lib")
#define UNICODE
#pragma warning(disable:6387 28251)

#include <windows.h>
#include <windowsx.h>
#include <tlhelp32.h>
#include <psapi.h>
#include <wintrust.h>
#include <softpub.h>
#include <mscat.h>
#include <richedit.h>
#include <shellapi.h>

#include <string>
#include <vector>
#include <algorithm>
#include <thread>
#include <chrono>
#include <cmath>
#include <sstream>
#include <iomanip>
#include <filesystem>
#include <fstream>

namespace fs = std::filesystem;

// IDs GUI
constexpr int ID_BTN_NORMAL = 201;
constexpr int ID_BTN_FORENSIC = 202;
constexpr int ID_BTN_CLEAR = 203;
constexpr int ID_RICH_LOG = 204;

enum class ScanMode { NORMAL, FORENSIC };
struct RegionInfo { LPVOID base; SIZE_T size; double ent; bool rwx; };

// Lista blanca para etiquetar pero NO saltar en NORMAL
static const std::vector<std::wstring> WHITELIST = {
    L"explorer.exe",
    L"svchost.exe",
    L"shellhost.exe",
    L"runtimebroker.exe",
    L"searchindexer.exe",
    L"msedgewebview2.exe"
};

// — Helpers — 

std::wstring Now() {
    auto t = std::chrono::system_clock::now();
    auto tt = std::chrono::system_clock::to_time_t(t);
    std::tm tm; localtime_s(&tm, &tt);
    std::wostringstream ss;
    ss << L"[" << std::setw(2) << std::setfill(L'0') << tm.tm_hour
        << L":" << std::setw(2) << tm.tm_min
        << L":" << std::setw(2) << tm.tm_sec << L"] ";
    return ss.str();
}

void AppendLog(HWND h, const std::wstring& txt, COLORREF col) {
    int len = GetWindowTextLengthW(h);
    SendMessageW(h, EM_SETSEL, len, len);
    CHARFORMAT2 cf = { sizeof(cf) };
    cf.dwMask = CFM_COLOR;
    cf.crTextColor = col;
    SendMessageW(h, EM_SETCHARFORMAT, SCF_SELECTION, (LPARAM)&cf);
    SendMessageW(h, EM_REPLACESEL, FALSE, (LPARAM)txt.c_str());
    SendMessageW(h, EM_SCROLLCARET, 0, 0);
}

bool IsWhitelisted(const std::wstring& name) {
    for (auto& w : WHITELIST)
        if (name == w) return true;
    return false;
}

bool IsProcessSigned(HANDLE proc) {
    wchar_t path[MAX_PATH];
    if (!GetModuleFileNameExW(proc, nullptr, path, _countof(path)))
        return false;
    std::wstring p(path);
    if (_wcsnicmp(p.c_str(), L"C:\\Windows\\", 10) == 0 ||
        _wcsnicmp(p.c_str(), L"C:\\Program Files\\", 16) == 0)
        return true;
    WINTRUST_FILE_INFO fileInfo{ sizeof(fileInfo), nullptr, path, nullptr };
    GUID policy = WINTRUST_ACTION_GENERIC_VERIFY_V2;
    WINTRUST_DATA data{ sizeof(data) };
    data.dwUIChoice = WTD_UI_NONE;
    data.fdwRevocationChecks = WTD_REVOKE_NONE;
    data.dwUnionChoice = WTD_CHOICE_FILE;
    data.pFile = &fileInfo;
    return WinVerifyTrust(nullptr, &policy, &data) == ERROR_SUCCESS;
}

// — Scaneo Memoria — 

std::vector<RegionInfo> ScanMemory(HANDLE proc, ScanMode mode) {
    SIZE_T minSz = (mode == ScanMode::NORMAL ? 0x1000 : 0x400);
    double thrEnt = (mode == ScanMode::NORMAL ? 7.0 : 6.5);
    std::vector<RegionInfo> regs;
    LPBYTE addr = nullptr;
    MEMORY_BASIC_INFORMATION mbi;
    while (VirtualQueryEx(proc, addr, &mbi, sizeof(mbi)) == sizeof(mbi)) {
        addr = (LPBYTE)mbi.BaseAddress + mbi.RegionSize;
        if ((mbi.Type != MEM_PRIVATE && mbi.Type != MEM_MAPPED) ||
            mbi.State != MEM_COMMIT || mbi.RegionSize < minSz)
            continue;
        bool rwx = (mbi.Protect & (PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY)) != 0;
        SIZE_T scanSz = std::min< SIZE_T >(mbi.RegionSize, 0x4000);
        std::vector<BYTE> buf(scanSz);
        SIZE_T got = 0;
        if (!ReadProcessMemory(proc, mbi.BaseAddress, buf.data(), scanSz, &got) || !got)
            continue;
        size_t freq[256] = {};
        for (SIZE_T i = 0; i < got; i++) freq[buf[i]]++;
        double ent = 0;
        for (int i = 0; i < 256; i++) if (freq[i]) {
            double p = (double)freq[i] / got;
            ent -= p * log2(p);
        }
        if ((mode == ScanMode::NORMAL && (rwx || ent >= thrEnt)) ||
            (mode == ScanMode::FORENSIC && rwx && ent >= 8.0)) {
            regs.push_back({ mbi.BaseAddress,mbi.RegionSize,ent,rwx });
        }
    }
    return regs;
}

// — Scaneo Hooks — 

std::vector<RegionInfo> ScanHooks(HANDLE proc, ScanMode mode) {
    SIZE_T minSz = (mode == ScanMode::NORMAL ? 0x2000 : 0x800);
    int diffThresh = (mode == ScanMode::NORMAL ? 8 : 4);
    std::vector<RegionInfo> hooks;
    HMODULE mods[256]; DWORD cb;
    if (!EnumProcessModulesEx(proc, mods, sizeof(mods), &cb, LIST_MODULES_ALL))
        return hooks;
    int count = cb / sizeof(HMODULE);
    for (int i = 0; i < count; i++) {
        wchar_t path[MAX_PATH];
        GetModuleFileNameExW(proc, mods[i], path, MAX_PATH);
        HANDLE hf = CreateFileW(path, GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING, 0, nullptr);
        if (hf == INVALID_HANDLE_VALUE) continue;
        HANDLE hm = CreateFileMappingW(hf, nullptr, PAGE_READONLY, 0, 0, nullptr);
        CloseHandle(hf);
        if (!hm) continue;
        LPBYTE map = (LPBYTE)MapViewOfFile(hm, FILE_MAP_READ, 0, 0, 0);
        CloseHandle(hm);
        if (!map) continue;
        auto dos = (IMAGE_DOS_HEADER*)map;
        auto nt = (IMAGE_NT_HEADERS*)(map + dos->e_lfanew);
        auto sec = IMAGE_FIRST_SECTION(nt);
        for (int s = 0; s < nt->FileHeader.NumberOfSections; s++) {
            if (strncmp((char*)sec[s].Name, ".text", 5)) continue;
            LPVOID base = (LPBYTE)mods[i] + sec[s].VirtualAddress;
            SIZE_T size = sec[s].Misc.VirtualSize;
            std::vector<BYTE> disk(size), mem(size);
            memcpy(disk.data(), map + sec[s].PointerToRawData, size);
            SIZE_T got = 0;
            ReadProcessMemory(proc, base, mem.data(), size, &got);
            int diffs = 0;
            for (SIZE_T k = 0; k < got; k++)
                if (disk[k] != mem[k] && ++diffs > diffThresh) break;
            if (diffs > diffThresh)
                hooks.push_back({ base,size,(double)diffs,false });
            break;
        }
        UnmapViewOfFile(map);
    }
    return hooks;
}

// — Scaneo Archivos — 

std::vector<std::pair<std::wstring, double>> ScanFiles(ScanMode mode) {
    double thr = (mode == ScanMode::NORMAL ? 7.0 : 8.0);
    std::vector<std::pair<std::wstring, double>> found;
    for (auto& e : fs::directory_iterator(fs::current_path())) {
        if (!e.is_regular_file()) continue;
        auto ext = e.path().extension().wstring();
        if (ext == L".dll" || ext == L".exe" || ext == L".efi" || ext == L".xml" || ext == L".json") {
            std::ifstream f(e.path(), std::ios::binary);
            std::vector<BYTE> buf((std::istreambuf_iterator<char>(f)), {});
            size_t n = buf.size();
            if (n < 256) continue;
            size_t freq[256] = {};
            for (auto b : buf) freq[b]++;
            double ent = 0;
            for (int i = 0; i < 256; i++) if (freq[i]) {
                double p = (double)freq[i] / n;
                ent -= p * log2(p);
            }
            if (ent >= thr) found.emplace_back(e.path().wstring(), ent);
        }
    }
    return found;
}

// — Driver del Scan — 

void DoScan(HWND rich, HWND btn, ScanMode mode) {
    AppendLog(rich, Now() + L"=== Scan Started ===\n", RGB(200, 200, 200));
    EnableWindow(btn, FALSE);

    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    PROCESSENTRY32 pe{ sizeof(pe) };
    Process32First(snap, &pe);
    do {
        DWORD pid = pe.th32ProcessID; if (pid < 4) continue;
        HANDLE proc = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
        if (!proc) continue;
        wchar_t nb[MAX_PATH]; GetModuleBaseNameW(proc, nullptr, nb, MAX_PATH);
        std::wstring name(nb);
        std::transform(name.begin(), name.end(), name.begin(), ::towlower);

        bool white = IsWhitelisted(name);
        bool sig = IsProcessSigned(proc);

        // FORÓNSICO: saltar sólo si es whitelist+firmado
        if (white && mode == ScanMode::FORENSIC && sig) {
            AppendLog(rich, Now() + L"[OK/SIGNED]   " + name + L"\n", RGB(100, 200, 100));
            CloseHandle(proc);
            continue;
        }

        // Etiqueta whitelist pero en NORMAL lo escanea
        if (white) {
            AppendLog(rich, Now() + L"[WHITE]       " + name + L"\n", RGB(0, 200, 200));
        }

        // Unsigned?
        if (!sig)
            AppendLog(rich, Now() + L"[UNSIGNED]    " + name + L"\n", RGB(255, 0, 0));
        else
            AppendLog(rich, Now() + L"[SCAN]        " + name + L"\n", RGB(150, 150, 150));

        auto regs = ScanMemory(proc, mode);
        auto hooks = ScanHooks(proc, mode);
        for (auto& r : regs) {
            if (mode == ScanMode::FORENSIC)
                AppendLog(rich, Now() + L"[FOR-DET]     " + name + L" E=" + std::to_wstring(r.ent) + L"\n", RGB(255, 0, 0));
            else if (r.rwx)
                AppendLog(rich, Now() + L"[RWX]         " + name + L" Addr=0x" + std::to_wstring((ULONG_PTR)r.base) + L"\n", RGB(255, 0, 0));
            else
                AppendLog(rich, Now() + L"[DETECT]      " + name + L" E=" + std::to_wstring(r.ent) + L"\n", RGB(255, 0, 0));
        }
        for (auto& h : hooks)
            AppendLog(rich, Now() + L"[HOOK]        " + name + L" Diffs=" + std::to_wstring((int)h.ent) + L"\n", RGB(255, 165, 0));
        if (regs.empty() && hooks.empty())
            AppendLog(rich, Now() + L"[OK]          " + name + L"\n", RGB(0, 200, 0));

        CloseHandle(proc);
    } while (Process32Next(snap, &pe));
    CloseHandle(snap);

    AppendLog(rich, Now() + L"=== File Scan ===\n", RGB(200, 200, 200));
    auto files = ScanFiles(mode);
    for (auto& f : files)
        AppendLog(rich, Now() + L"[FILE-DET]    " + f.first + L" E=" + std::to_wstring(f.second) + L"\n", RGB(255, 0, 0));
    if (files.empty())
        AppendLog(rich, Now() + L"[FILES OK]\n", RGB(0, 200, 0));

    AppendLog(rich, Now() + L"=== Scan Complete ===\n", RGB(200, 200, 200));
    EnableWindow(btn, TRUE);
}

// — WndProc + GUI — 

LRESULT CALLBACK WndProc(HWND hwnd, UINT msg, WPARAM wp, LPARAM lp) {
    static HWND btnN, btnF, btnC, rich;
    static HINSTANCE hInst;
    switch (msg) {
    case WM_CREATE: {
        hInst = ((LPCREATESTRUCT)lp)->hInstance;
        LoadLibraryW(L"Msftedit.dll");

        btnN = CreateWindowW(L"BUTTON", L"Normal Scan",
            WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
            10, 10, 120, 30, hwnd,
            (HMENU)MAKEINTRESOURCE(ID_BTN_NORMAL),
            hInst, nullptr);

        btnF = CreateWindowW(L"BUTTON", L"Forensic Scan",
            WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
            140, 10, 120, 30, hwnd,
            (HMENU)MAKEINTRESOURCE(ID_BTN_FORENSIC),
            hInst, nullptr);

        btnC = CreateWindowW(L"BUTTON", L"Clear Log",
            WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
            270, 10, 120, 30, hwnd,
            (HMENU)MAKEINTRESOURCE(ID_BTN_CLEAR),
            hInst, nullptr);

        rich = CreateWindowExW(WS_EX_CLIENTEDGE, L"RICHEDIT50W", L"",
            WS_CHILD | WS_VISIBLE | WS_VSCROLL | WS_HSCROLL |
            ES_MULTILINE | ES_READONLY | ES_AUTOVSCROLL,
            10, 50, 800, 550, hwnd,
            (HMENU)MAKEINTRESOURCE(ID_RICH_LOG),
            hInst, nullptr);

        HFONT hf = CreateFontW(14, 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE,
            DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS,
            DEFAULT_QUALITY, FF_DONTCARE, L"Consolas");
        SendMessageW(rich, WM_SETFONT, (WPARAM)hf, TRUE);
        SendMessageW(rich, EM_SETBKGNDCOLOR, 0, RGB(0, 0, 0));
        break;
    }

    case WM_COMMAND:
        switch (LOWORD(wp)) {
        case ID_BTN_NORMAL:
            SetWindowTextW(rich, L"");
            std::thread(DoScan, rich, btnN, ScanMode::NORMAL).detach();
            break;
        case ID_BTN_FORENSIC:
            SetWindowTextW(rich, L"");
            std::thread(DoScan, rich, btnF, ScanMode::FORENSIC).detach();
            break;
        case ID_BTN_CLEAR:
            SetWindowTextW(rich, L"");
            break;
        }
        break;

    case WM_SIZE: {
        RECT rc; GetClientRect(hwnd, &rc);
        MoveWindow(btnN, 10, 10, 120, 30, TRUE);
        MoveWindow(btnF, 140, 10, 120, 30, TRUE);
        MoveWindow(btnC, 270, 10, 120, 30, TRUE);
        MoveWindow(rich, 10, 50, rc.right - 20, rc.bottom - 60, TRUE);
        break;
    }

    case WM_DESTROY:
        PostQuitMessage(0);
        break;

    default:
        return DefWindowProcW(hwnd, msg, wp, lp);
    }
    return 0;
}

// — Entry Points — 

int WINAPI wWinMain(HINSTANCE hInst, HINSTANCE, PWSTR, int nShow) {
    WNDCLASSW wc = {};
    wc.lpfnWndProc = WndProc;
    wc.hInstance = hInst;
    wc.lpszClassName = L"DarkShellDetector";
    wc.hbrBackground = (HBRUSH)GetStockObject(BLACK_BRUSH);
    wc.hCursor = LoadCursor(nullptr, IDC_ARROW);
    RegisterClassW(&wc);

    HWND hwnd = CreateWindowExW(
        0, wc.lpszClassName,
        L"APT-Level Shellcode Detector - Developed by <starls/>",
        WS_OVERLAPPEDWINDOW,
        CW_USEDEFAULT, CW_USEDEFAULT, 860, 640,
        nullptr, nullptr, hInst, nullptr
    );
    if (!hwnd) return 0;
    ShowWindow(hwnd, nShow);
    UpdateWindow(hwnd);

    MSG msg;
    while (GetMessageW(&msg, nullptr, 0, 0)) {
        TranslateMessage(&msg);
        DispatchMessageW(&msg);
    }
    return 0;
}

extern "C" int WINAPI WinMain(HINSTANCE hA, HINSTANCE hP, LPSTR lpC, int nS) {
    return wWinMain(hA, hP, GetCommandLineW(), nS);
}
