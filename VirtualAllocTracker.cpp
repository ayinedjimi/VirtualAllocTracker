/*******************************************************************************
 * VirtualAllocTracker - Tracker Allocations Mémoire Suspectes
 *
 * Ayi NEDJIMI Consultants - Forensics & Security Suite
 * Série 3 : Outils Forensics Mémoire & Processus
 *
 * Description : Monitoring allocations VirtualAlloc/VirtualProtect,
 *               détection pages RWX, timeline forensics
 *
 * Fonctionnalités :
 *   - Polling périodique VirtualQueryEx sur processus sélectionnés
 *   - Détection pages RWX (READ+WRITE+EXECUTE) hautement suspectes
 *   - Détection changements protection MEM_COMMIT → PAGE_EXECUTE
 *   - Timeline allocations avec horodatage
 *   - Alertes temps réel sur allocations dangereuses
 *   - Export rapport CSV UTF-8 BOM
 *
 * Compilation : Voir go.bat
 ******************************************************************************/

#define UNICODE
#define _UNICODE
#define WIN32_LEAN_AND_MEAN

#include <windows.h>
#include <commctrl.h>
#include <tlhelp32.h>
#include <psapi.h>
#include <string>
#include <vector>
#include <thread>
#include <mutex>
#include <sstream>
#include <fstream>
#include <iomanip>
#include <map>
#include <chrono>

#pragma comment(lib, "comctl32.lib")
#pragma comment(lib, "psapi.lib")

// Constantes
#define WM_ALERT (WM_USER + 1)
#define IDC_LISTVIEW 1001
#define IDC_COMBO_PROCESS 1002
#define IDC_BTN_START 1003
#define IDC_BTN_STOP 1004
#define IDC_BTN_EXPORT 1005
#define IDC_CHECK_RWX 1006
#define IDC_STATUS 1007

// RAII Handle Wrapper
class AutoHandle {
    HANDLE h;
public:
    AutoHandle(HANDLE handle = INVALID_HANDLE_VALUE) : h(handle) {}
    ~AutoHandle() { if (h != INVALID_HANDLE_VALUE && h != NULL) CloseHandle(h); }
    operator HANDLE() const { return h; }
    HANDLE get() const { return h; }
    bool isValid() const { return h != INVALID_HANDLE_VALUE && h != NULL; }
};

// Structure Allocation Event
struct AllocationEvent {
    std::wstring timestamp;
    DWORD pid;
    std::wstring processName;
    PVOID address;
    SIZE_T size;
    DWORD protection;
    std::wstring eventType;  // "Allocation" ou "Protection Change"
    std::wstring alert;
};

// Globales
HWND g_hListView = NULL;
HWND g_hComboProcess = NULL;
HWND g_hStatus = NULL;
HWND g_hCheckRWX = NULL;
std::vector<AllocationEvent> g_events;
std::mutex g_mutex;
std::wofstream g_logFile;
DWORD g_selectedPID = 0;
bool g_monitoring = false;
std::map<PVOID, DWORD> g_previousProtections;

// Prototypes
LRESULT CALLBACK WndProc(HWND, UINT, WPARAM, LPARAM);
void InitListView(HWND hList);
void PopulateProcessList();
void Log(const std::wstring& message);
void StartMonitoring();
void StopMonitoring();
void MonitoringThread();
void ExportToCSV();
std::wstring GetProtectionString(DWORD protect);
std::wstring GetTimestamp();

// Point d'entrée
int WINAPI wWinMain(HINSTANCE hInstance, HINSTANCE, LPWSTR, int nCmdShow) {
    // Initialiser log
    wchar_t tempPath[MAX_PATH];
    GetTempPathW(MAX_PATH, tempPath);
    std::wstring logPath = std::wstring(tempPath) + L"WinTools_VirtualAllocTracker_log.txt";
    g_logFile.open(logPath, std::ios::app);
    g_logFile.imbue(std::locale(g_logFile.getloc(), new std::codecvt_utf8<wchar_t>));

    Log(L"========== VirtualAllocTracker - Démarrage ==========");

    // Activer privilège SeDebugPrivilege
    HANDLE hToken;
    if (OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES, &hToken)) {
        TOKEN_PRIVILEGES tp;
        LUID luid;
        LookupPrivilegeValueW(NULL, SE_DEBUG_NAME, &luid);
        tp.PrivilegeCount = 1;
        tp.Privileges[0].Luid = luid;
        tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
        AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(tp), NULL, NULL);
        CloseHandle(hToken);
    }

    // Initialiser Common Controls
    INITCOMMONCONTROLSEX icex = { sizeof(INITCOMMONCONTROLSEX), ICC_LISTVIEW_CLASSES };
    InitCommonControlsEx(&icex);

    // Classe de fenêtre
    WNDCLASSEXW wc = { sizeof(WNDCLASSEXW) };
    wc.lpfnWndProc = WndProc;
    wc.hInstance = hInstance;
    wc.hCursor = LoadCursor(NULL, IDC_ARROW);
    wc.hbrBackground = (HBRUSH)(COLOR_WINDOW + 1);
    wc.lpszClassName = L"VirtualAllocTrackerClass";
    wc.hIcon = LoadIcon(NULL, IDI_ASTERISK);
    wc.hIconSm = LoadIcon(NULL, IDI_ASTERISK);

    if (!RegisterClassExW(&wc)) {
        MessageBoxW(NULL, L"Échec d'enregistrement de la classe!", L"Erreur", MB_ICONERROR);
        return 1;
    }

    // Créer fenêtre
    HWND hWnd = CreateWindowExW(
        WS_EX_APPWINDOW,
        wc.lpszClassName,
        L"VirtualAlloc Tracker - Ayi NEDJIMI Consultants",
        WS_OVERLAPPEDWINDOW,
        CW_USEDEFAULT, CW_USEDEFAULT, 1300, 700,
        NULL, NULL, hInstance, NULL
    );

    if (!hWnd) {
        MessageBoxW(NULL, L"Échec de création de fenêtre!", L"Erreur", MB_ICONERROR);
        return 1;
    }

    ShowWindow(hWnd, nCmdShow);
    UpdateWindow(hWnd);

    // Boucle de messages
    MSG msg;
    while (GetMessage(&msg, NULL, 0, 0)) {
        TranslateMessage(&msg);
        DispatchMessage(&msg);
    }

    g_logFile.close();
    return (int)msg.wParam;
}

// Procédure de fenêtre
LRESULT CALLBACK WndProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    static HINSTANCE hInst;

    switch (msg) {
    case WM_CREATE: {
        hInst = ((LPCREATESTRUCT)lParam)->hInstance;

        // Combo box processus
        CreateWindowW(L"STATIC", L"Processus cible:",
            WS_CHILD | WS_VISIBLE | SS_LEFT,
            10, 15, 120, 20, hWnd, NULL, hInst, NULL);

        g_hComboProcess = CreateWindowW(L"COMBOBOX", L"",
            WS_CHILD | WS_VISIBLE | CBS_DROPDOWNLIST | WS_VSCROLL,
            140, 10, 350, 300, hWnd, (HMENU)IDC_COMBO_PROCESS, hInst, NULL);

        PopulateProcessList();

        // Checkbox filtrage RWX
        g_hCheckRWX = CreateWindowW(L"BUTTON", L"Filtrer RWX uniquement",
            WS_CHILD | WS_VISIBLE | BS_AUTOCHECKBOX,
            500, 13, 200, 20, hWnd, (HMENU)IDC_CHECK_RWX, hInst, NULL);

        // ListView
        g_hListView = CreateWindowExW(
            0, WC_LISTVIEWW, L"",
            WS_CHILD | WS_VISIBLE | LVS_REPORT | LVS_SINGLESEL | WS_BORDER,
            10, 50, 1260, 540,
            hWnd, (HMENU)IDC_LISTVIEW, hInst, NULL
        );
        InitListView(g_hListView);

        // Boutons
        CreateWindowW(L"BUTTON", L"Démarrer Monitoring",
            WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
            710, 10, 180, 30, hWnd, (HMENU)IDC_BTN_START, hInst, NULL);

        CreateWindowW(L"BUTTON", L"Arrêter",
            WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON | WS_DISABLED,
            900, 10, 120, 30, hWnd, (HMENU)IDC_BTN_STOP, hInst, NULL);

        CreateWindowW(L"BUTTON", L"Exporter CSV",
            WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
            1030, 10, 130, 30, hWnd, (HMENU)IDC_BTN_EXPORT, hInst, NULL);

        // Barre de statut
        g_hStatus = CreateWindowW(L"STATIC", L"Sélectionnez un processus et démarrez le monitoring",
            WS_CHILD | WS_VISIBLE | SS_LEFT,
            10, 600, 1260, 20, hWnd, (HMENU)IDC_STATUS, hInst, NULL);

        return 0;
    }

    case WM_COMMAND:
        switch (LOWORD(wParam)) {
        case IDC_BTN_START: {
            int sel = ComboBox_GetCurSel(g_hComboProcess);
            if (sel == CB_ERR) {
                MessageBoxW(hWnd, L"Veuillez sélectionner un processus", L"Info", MB_ICONINFORMATION);
                break;
            }

            g_selectedPID = (DWORD)ComboBox_GetItemData(g_hComboProcess, sel);
            StartMonitoring();
            EnableWindow(GetDlgItem(hWnd, IDC_BTN_START), FALSE);
            EnableWindow(GetDlgItem(hWnd, IDC_BTN_STOP), TRUE);
            break;
        }
        case IDC_BTN_STOP:
            StopMonitoring();
            EnableWindow(GetDlgItem(hWnd, IDC_BTN_START), TRUE);
            EnableWindow(GetDlgItem(hWnd, IDC_BTN_STOP), FALSE);
            break;
        case IDC_BTN_EXPORT:
            ExportToCSV();
            break;
        }
        break;

    case WM_ALERT: {
        // Nouvelle allocation détectée
        MessageBeep(MB_ICONWARNING);
        break;
    }

    case WM_DESTROY:
        g_monitoring = false;
        PostQuitMessage(0);
        return 0;
    }

    return DefWindowProcW(hWnd, msg, wParam, lParam);
}

// Initialiser ListView
void InitListView(HWND hList) {
    ListView_SetExtendedListViewStyle(hList, LVS_EX_FULLROWSELECT | LVS_EX_GRIDLINES);

    LVCOLUMNW col = { LVCF_TEXT | LVCF_WIDTH };
    const wchar_t* headers[] = { L"Timestamp", L"PID", L"Processus", L"Adresse", L"Taille", L"Protection", L"Type", L"Alerte" };
    int widths[] = { 160, 60, 150, 120, 100, 120, 150, 280 };

    for (int i = 0; i < 8; i++) {
        col.pszText = (LPWSTR)headers[i];
        col.cx = widths[i];
        ListView_InsertColumn(hList, i, &col);
    }
}

// Peupler liste processus
void PopulateProcessList() {
    ComboBox_ResetContent(g_hComboProcess);

    AutoHandle hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (!hSnapshot.isValid()) return;

    PROCESSENTRY32W pe = { sizeof(PROCESSENTRY32W) };
    if (Process32FirstW(hSnapshot, &pe)) {
        do {
            if (pe.th32ProcessID == 0 || pe.th32ProcessID == 4) continue;

            std::wstringstream ss;
            ss << pe.szExeFile << L" (PID: " << pe.th32ProcessID << L")";

            int index = ComboBox_AddString(g_hComboProcess, ss.str().c_str());
            ComboBox_SetItemData(g_hComboProcess, index, pe.th32ProcessID);

        } while (Process32NextW(hSnapshot, &pe));
    }

    ComboBox_SetCurSel(g_hComboProcess, 0);
}

// Logging
void Log(const std::wstring& message) {
    SYSTEMTIME st;
    GetLocalTime(&st);

    std::wstringstream ss;
    ss << std::setfill(L'0')
       << std::setw(2) << st.wHour << L":"
       << std::setw(2) << st.wMinute << L":"
       << std::setw(2) << st.wSecond << L" - " << message << std::endl;

    if (g_logFile.is_open()) {
        g_logFile << ss.str();
        g_logFile.flush();
    }
}

// Démarrer monitoring
void StartMonitoring() {
    g_monitoring = true;
    g_previousProtections.clear();
    ListView_DeleteAllItems(g_hListView);
    g_events.clear();

    Log(L"Monitoring démarré pour PID " + std::to_wstring(g_selectedPID));
    SetWindowTextW(g_hStatus, L"Monitoring actif...");

    std::thread(MonitoringThread).detach();
}

// Arrêter monitoring
void StopMonitoring() {
    g_monitoring = false;
    Log(L"Monitoring arrêté");
    SetWindowTextW(g_hStatus, L"Monitoring arrêté");
}

// Thread de monitoring
void MonitoringThread() {
    while (g_monitoring) {
        AutoHandle hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, g_selectedPID);

        if (!hProcess.isValid()) {
            Log(L"ERREUR: Processus inaccessible ou terminé");
            PostMessage(GetParent(g_hListView), WM_COMMAND, IDC_BTN_STOP, 0);
            break;
        }

        // Obtenir nom processus
        wchar_t processName[MAX_PATH];
        DWORD size = MAX_PATH;
        QueryFullProcessImageNameW(hProcess, 0, processName, &size);
        std::wstring procName = processName;
        size_t pos = procName.find_last_of(L"\\");
        if (pos != std::wstring::npos) {
            procName = procName.substr(pos + 1);
        }

        // Scanner régions mémoire
        PVOID address = NULL;
        MEMORY_BASIC_INFORMATION mbi;

        while (VirtualQueryEx(hProcess, address, &mbi, sizeof(mbi)) == sizeof(mbi)) {
            if (mbi.State == MEM_COMMIT) {
                // Vérifier si c'est une nouvelle région ou changement protection
                bool isRWX = (mbi.Protect & PAGE_EXECUTE_READWRITE) != 0;
                bool isRX = (mbi.Protect & PAGE_EXECUTE_READ) != 0;
                bool isNew = (g_previousProtections.find(mbi.BaseAddress) == g_previousProtections.end());
                bool protectionChanged = false;

                if (!isNew) {
                    DWORD oldProtect = g_previousProtections[mbi.BaseAddress];
                    protectionChanged = (oldProtect != mbi.Protect);

                    // Détecter changement vers EXECUTE
                    if (!(oldProtect & (PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE)) &&
                        (mbi.Protect & (PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE))) {

                        AllocationEvent event;
                        event.timestamp = GetTimestamp();
                        event.pid = g_selectedPID;
                        event.processName = procName;
                        event.address = mbi.BaseAddress;
                        event.size = mbi.RegionSize;
                        event.protection = mbi.Protect;
                        event.eventType = L"Protection Change";
                        event.alert = L"Changement vers EXECUTE détecté!";

                        std::lock_guard<std::mutex> lock(g_mutex);
                        g_events.push_back(event);

                        // Ajouter à ListView
                        LVITEMW item = { LVIF_TEXT };
                        item.iItem = ListView_GetItemCount(g_hListView);
                        item.pszText = (LPWSTR)event.timestamp.c_str();
                        ListView_InsertItem(g_hListView, &item);

                        std::wstring pidStr = std::to_wstring(event.pid);
                        ListView_SetItemText(g_hListView, item.iItem, 1, (LPWSTR)pidStr.c_str());
                        ListView_SetItemText(g_hListView, item.iItem, 2, (LPWSTR)event.processName.c_str());

                        std::wstringstream addrSS;
                        addrSS << L"0x" << std::hex << std::uppercase << (ULONG_PTR)event.address;
                        std::wstring addrStr = addrSS.str();
                        ListView_SetItemText(g_hListView, item.iItem, 3, (LPWSTR)addrStr.c_str());

                        std::wstring sizeStr = std::to_wstring(event.size);
                        ListView_SetItemText(g_hListView, item.iItem, 4, (LPWSTR)sizeStr.c_str());

                        std::wstring protStr = GetProtectionString(event.protection);
                        ListView_SetItemText(g_hListView, item.iItem, 5, (LPWSTR)protStr.c_str());
                        ListView_SetItemText(g_hListView, item.iItem, 6, (LPWSTR)event.eventType.c_str());
                        ListView_SetItemText(g_hListView, item.iItem, 7, (LPWSTR)event.alert.c_str());

                        PostMessage(GetParent(g_hListView), WM_ALERT, 0, 0);
                        Log(L"Alerte: " + event.alert + L" @ " + addrStr);
                    }
                }

                // Détecter nouvelle allocation RWX
                if (isNew && isRWX) {
                    AllocationEvent event;
                    event.timestamp = GetTimestamp();
                    event.pid = g_selectedPID;
                    event.processName = procName;
                    event.address = mbi.BaseAddress;
                    event.size = mbi.RegionSize;
                    event.protection = mbi.Protect;
                    event.eventType = L"Allocation";
                    event.alert = L"Allocation RWX hautement suspecte!";

                    bool filterRWX = (Button_GetCheck(g_hCheckRWX) == BST_CHECKED);

                    std::lock_guard<std::mutex> lock(g_mutex);
                    g_events.push_back(event);

                    if (!filterRWX || isRWX) {
                        // Ajouter à ListView
                        LVITEMW item = { LVIF_TEXT };
                        item.iItem = ListView_GetItemCount(g_hListView);
                        item.pszText = (LPWSTR)event.timestamp.c_str();
                        ListView_InsertItem(g_hListView, &item);

                        std::wstring pidStr = std::to_wstring(event.pid);
                        ListView_SetItemText(g_hListView, item.iItem, 1, (LPWSTR)pidStr.c_str());
                        ListView_SetItemText(g_hListView, item.iItem, 2, (LPWSTR)event.processName.c_str());

                        std::wstringstream addrSS;
                        addrSS << L"0x" << std::hex << std::uppercase << (ULONG_PTR)event.address;
                        std::wstring addrStr = addrSS.str();
                        ListView_SetItemText(g_hListView, item.iItem, 3, (LPWSTR)addrStr.c_str());

                        std::wstring sizeStr = std::to_wstring(event.size);
                        ListView_SetItemText(g_hListView, item.iItem, 4, (LPWSTR)sizeStr.c_str());

                        std::wstring protStr = GetProtectionString(event.protection);
                        ListView_SetItemText(g_hListView, item.iItem, 5, (LPWSTR)protStr.c_str());
                        ListView_SetItemText(g_hListView, item.iItem, 6, (LPWSTR)event.eventType.c_str());
                        ListView_SetItemText(g_hListView, item.iItem, 7, (LPWSTR)event.alert.c_str());

                        PostMessage(GetParent(g_hListView), WM_ALERT, 0, 0);
                        Log(L"Alerte: " + event.alert + L" @ " + addrStr);
                    }
                }

                g_previousProtections[mbi.BaseAddress] = mbi.Protect;
            }

            address = (PVOID)((ULONG_PTR)mbi.BaseAddress + mbi.RegionSize);
        }

        Sleep(1000);  // Polling chaque seconde
    }
}

// Obtenir timestamp
std::wstring GetTimestamp() {
    SYSTEMTIME st;
    GetLocalTime(&st);

    std::wstringstream ss;
    ss << std::setfill(L'0')
       << st.wYear << L"-"
       << std::setw(2) << st.wMonth << L"-"
       << std::setw(2) << st.wDay << L" "
       << std::setw(2) << st.wHour << L":"
       << std::setw(2) << st.wMinute << L":"
       << std::setw(2) << st.wSecond;

    return ss.str();
}

// Obtenir string protection
std::wstring GetProtectionString(DWORD protect) {
    if (protect & PAGE_EXECUTE_READWRITE) return L"RWX";
    if (protect & PAGE_EXECUTE_READ) return L"RX";
    if (protect & PAGE_EXECUTE) return L"X";
    if (protect & PAGE_READWRITE) return L"RW";
    if (protect & PAGE_READONLY) return L"R";
    return L"Unknown";
}

// Export CSV
void ExportToCSV() {
    wchar_t filename[MAX_PATH] = L"virtualalloc_tracking.csv";

    OPENFILENAMEW ofn = { sizeof(OPENFILENAMEW) };
    ofn.hwndOwner = GetParent(g_hListView);
    ofn.lpstrFilter = L"CSV Files\0*.csv\0All Files\0*.*\0";
    ofn.lpstrFile = filename;
    ofn.nMaxFile = MAX_PATH;
    ofn.Flags = OFN_OVERWRITEPROMPT;

    if (!GetSaveFileNameW(&ofn)) return;

    std::wofstream csvFile(filename, std::ios::binary);

    // UTF-8 BOM
    const unsigned char bom[] = { 0xEF, 0xBB, 0xBF };
    csvFile.write((wchar_t*)bom, sizeof(bom));
    csvFile.imbue(std::locale(csvFile.getloc(), new std::codecvt_utf8<wchar_t, 0x10ffff, std::consume_header>));

    // En-têtes
    csvFile << L"Timestamp,PID,Processus,Adresse,Taille,Protection,Type,Alerte\n";

    // Données
    std::lock_guard<std::mutex> lock(g_mutex);
    for (const auto& event : g_events) {
        csvFile << L"\"" << event.timestamp << L"\","
                << event.pid << L","
                << L"\"" << event.processName << L"\","
                << L"0x" << std::hex << std::uppercase << (ULONG_PTR)event.address << L","
                << std::dec << event.size << L","
                << L"\"" << GetProtectionString(event.protection) << L"\","
                << L"\"" << event.eventType << L"\","
                << L"\"" << event.alert << L"\"\n";
    }

    csvFile.close();

    std::wstring msg = L"Export CSV terminé: " + std::wstring(filename);
    MessageBoxW(GetParent(g_hListView), msg.c_str(), L"Succès", MB_ICONINFORMATION);
    Log(msg);
}
