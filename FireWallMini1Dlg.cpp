
// FireWallMini1Dlg.cpp : implementation file
//

#include "pch.h"
#include "framework.h"
#include "FireWallMini1.h"
#include "FireWallMini1Dlg.h"
#include "afxdialogex.h"
#include "DebugLog.h"

#include <pcap.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <iphlpapi.h>
#include <vector>
#include <string>



#ifdef _DEBUG
#define new DEBUG_NEW
#endif

// Định nghĩa Custom Message để Thread bắt gói gửi log về UI Thread
#define WM_UPDATE_LOG (WM_USER + 100)

// Cấu trúc Ethernet Header (14 bytes)
#pragma pack(push, 1)
struct EthernetHeader {
	unsigned char dest[6];
	unsigned char source[6];
	unsigned short type; // Protocol type (IP, ARP, etc.)
};

// Cấu trúc IP Header (Cơ bản cho IPv4)
struct IpHeader {
	unsigned char  ver_ihl;        // Version (4 bits) + Internet Header Length (4 bits)
	unsigned char  tos;            // Type of service 
	unsigned short tlen;           // Total length 
	unsigned short identification; // Identification
	unsigned short flags_fo;       // Flags (3 bits) + Fragment Offset (13 bits)
	unsigned char  ttl;            // Time to live
	unsigned char  proto;          // Protocol
	unsigned short crc;            // Header checksum
	unsigned char  saddr[4];       // Source address
	unsigned char  daddr[4];       // Destination address
};

// Cấu trúc TCP Header
struct TcpHeader {
	unsigned short sport; // Source port
	unsigned short dport; // Destination port
	unsigned int   seq;   // Sequence number
	unsigned int   ack;   // Acknowledgement number
	unsigned char  offset_res;  // Data offset + Reserved
	unsigned char  flags;       // Flags
	unsigned short win;         // Window size
	unsigned short sum;         // Checksum
	unsigned short urp;         // Urgent pointer
};

// Cấu trúc UDP Header
struct UdpHeader {
	unsigned short sport; // Source port
	unsigned short dport; // Destination port
	unsigned short len;   // Datagram length
	unsigned short crc;   // Checksum
};
#pragma pack(pop)

// Struct dùng để gửi dữ liệu từ Thread về UI
struct LogData {
	CString time;
	CString protocol;
	CString srcIP;
	CString srcPort;
	CString dstIP;
	CString dstPort;
	CString matchedRule;
};


// CAboutDlg dialog used for App About

class CAboutDlg : public CDialogEx
{
public:
	CAboutDlg();

// Dialog Data
#ifdef AFX_DESIGN_TIME
	enum { IDD = IDD_ABOUTBOX };
#endif

	protected:
	virtual void DoDataExchange(CDataExchange* pDX);    // DDX/DDV support

// Implementation
protected:
	DECLARE_MESSAGE_MAP()
};

CAboutDlg::CAboutDlg() : CDialogEx(IDD_ABOUTBOX)
{
}

void CAboutDlg::DoDataExchange(CDataExchange* pDX)
{
	CDialogEx::DoDataExchange(pDX);
}

BEGIN_MESSAGE_MAP(CAboutDlg, CDialogEx)
END_MESSAGE_MAP()


// CFireWallMini1Dlg dialog



CFireWallMini1Dlg::CFireWallMini1Dlg(CWnd* pParent /*=nullptr*/)
	: CDialogEx(IDD_FIREWALLMINI1_DIALOG, pParent)
	// --- KHỞI TẠO GIÁ TRỊ MẶC ĐỊNH (Initializer List) ---
	, m_adhandle(nullptr)
	, m_isCapturing(false)
	, m_pCaptureThread(nullptr)
	, m_cntTotal(0)
	, m_cntTcp(0)
	, m_cntUdp(0)
	, m_cntIcmp(0)
	, m_debugPacketCount(0)
	// ----------------------------------------------------
{
	m_hIcon = AfxGetApp()->LoadIcon(IDR_MAINFRAME);
}

void CFireWallMini1Dlg::DoDataExchange(CDataExchange* pDX)
{
	CDialogEx::DoDataExchange(pDX);
	DDX_Control(pDX, IDC_LIST_LOG, m_listLog);
	DDX_Control(pDX, IDC_BTN_START, m_btnStart);
	DDX_Control(pDX, IDC_BTN_STOP, m_btnStop);
	DDX_Control(pDX, IDC_STATIC_TOTAL, m_strTotal);
	DDX_Control(pDX, IDC_STATIC_TCP, m_strTcp);
	DDX_Control(pDX, IDC_STATIC_UDP, m_strUdp);
	DDX_Control(pDX, IDC_STATIC_ICMP, m_strIcmp);
	DDX_Control(pDX, IDC_COMBO_ADAPTER, m_cbAdapter);
	DDX_Control(pDX, IDC_BTN_CLEAR, m_btnClear);
	DDX_Control(pDX, IDC_STATIC_ROW_COUNT, m_strRowCount);
	DDX_Control(pDX, IDC_STATIC_RULES, m_staticRules);
}

BEGIN_MESSAGE_MAP(CFireWallMini1Dlg, CDialogEx)
	ON_WM_SYSCOMMAND()
	ON_WM_PAINT()
	ON_WM_QUERYDRAGICON()
	ON_BN_CLICKED(IDC_BTN_START, &CFireWallMini1Dlg::OnBnClickedBtnStart)
	ON_BN_CLICKED(IDC_BTN_STOP, &CFireWallMini1Dlg::OnBnClickedBtnStop)
	ON_BN_CLICKED(IDC_BTN_CLEAR, &CFireWallMini1Dlg::OnBnClickedBtnClear)

	ON_MESSAGE(WM_UPDATE_LOG, &CFireWallMini1Dlg::OnUpdateLog)
	
END_MESSAGE_MAP()


// CFireWallMini1Dlg message handlers

BOOL CFireWallMini1Dlg::OnInitDialog()
{
	CDialogEx::OnInitDialog();

	// Add "About..." menu item to system menu.

	// IDM_ABOUTBOX must be in the system command range.
	ASSERT((IDM_ABOUTBOX & 0xFFF0) == IDM_ABOUTBOX);
	ASSERT(IDM_ABOUTBOX < 0xF000);

	CMenu* pSysMenu = GetSystemMenu(FALSE);
	if (pSysMenu != nullptr)
	{
		BOOL bNameValid;
		CString strAboutMenu;
		bNameValid = strAboutMenu.LoadString(IDS_ABOUTBOX);
		ASSERT(bNameValid);
		if (!strAboutMenu.IsEmpty())
		{
			pSysMenu->AppendMenu(MF_SEPARATOR);
			pSysMenu->AppendMenu(MF_STRING, IDM_ABOUTBOX, strAboutMenu);
		}
	}

	// Set the icon for this dialog.  The framework does this automatically
	//  when the application's main window is not a dialog
	SetIcon(m_hIcon, TRUE);			// Set big icon
	SetIcon(m_hIcon, FALSE);		// Set small icon

	// TODO: Add extra initialization here
	// 
	
	// Khởi tạo biến đếm
	m_cntTotal = m_cntTcp = m_cntUdp = m_cntIcmp = 0;
	m_isCapturing = false;
	m_adhandle = nullptr;

	// Lấy danh sách Adapter bằng Npcap
	pcap_if_t* alldevs;
	pcap_if_t* d;
	char errbuf[PCAP_ERRBUF_SIZE];

	// Xóa dữ liệu cũ trong ComboBox
	m_cbAdapter.ResetContent();
	m_cbAdapter.AddString(_T("-- Chọn adapter --"));
	m_adapterNames.clear();
	m_adapterNames.push_back(""); // Dummy cho index 0

	if (pcap_findalldevs(&alldevs, errbuf) == -1) {
		MessageBox(_T("Lỗi tìm adapter: ") + CString(errbuf));
	}
	else {
		for (d = alldevs; d; d = d->next) {
			CString strDesc;
			if (d->description)
				strDesc = CString(d->description);
			else
				strDesc = CString(d->name);

			m_cbAdapter.AddString(strDesc);
			m_adapterNames.push_back(d->name); // Lưu tên hệ thống để dùng khi open
		}
		pcap_freealldevs(alldevs);
	}
	m_cbAdapter.SetCurSel(0);

	// Hiển thị danh sách Rule đang kích hoạt
	CString strRulesContent = 
		_T("Ghi hard code sau\n")
		/*_T("Rule 1: Log mọi gói UDP\n")
		_T("Rule 2: Log mọi gói TCP\n")
		_T("Rule 3: Log gói từ IP 192.168.1.10")*/
		;

	m_staticRules.SetWindowText(strRulesContent);

	// Cấu hình List Control
	m_listLog.SetExtendedStyle(LVS_EX_FULLROWSELECT | LVS_EX_GRIDLINES);
	m_listLog.InsertColumn(0, _T("Time"), LVCFMT_LEFT, 90);
	m_listLog.InsertColumn(1, _T("Protocol"), LVCFMT_LEFT, 60);
	m_listLog.InsertColumn(2, _T("Src IP"), LVCFMT_LEFT, 100);
	m_listLog.InsertColumn(3, _T("Src Port"), LVCFMT_LEFT, 60);
	m_listLog.InsertColumn(4, _T("Dst IP"), LVCFMT_LEFT, 100);
	m_listLog.InsertColumn(5, _T("Dst Port"), LVCFMT_LEFT, 60);
	m_listLog.InsertColumn(6, _T("Matched Rule"), LVCFMT_LEFT, 150);


	return TRUE;  // return TRUE  unless you set the focus to a control
}

void CFireWallMini1Dlg::OnSysCommand(UINT nID, LPARAM lParam)
{
	if ((nID & 0xFFF0) == IDM_ABOUTBOX)
	{
		CAboutDlg dlgAbout;
		dlgAbout.DoModal();
	}
	else
	{
		CDialogEx::OnSysCommand(nID, lParam);
	}
}

// If you add a minimize button to your dialog, you will need the code below
//  to draw the icon.  For MFC applications using the document/view model,
//  this is automatically done for you by the framework.

void CFireWallMini1Dlg::OnPaint()
{
	if (IsIconic())
	{
		CPaintDC dc(this); // device context for painting

		SendMessage(WM_ICONERASEBKGND, reinterpret_cast<WPARAM>(dc.GetSafeHdc()), 0);

		// Center icon in client rectangle
		int cxIcon = GetSystemMetrics(SM_CXICON);
		int cyIcon = GetSystemMetrics(SM_CYICON);
		CRect rect;
		GetClientRect(&rect);
		int x = (rect.Width() - cxIcon + 1) / 2;
		int y = (rect.Height() - cyIcon + 1) / 2;

		// Draw the icon
		dc.DrawIcon(x, y, m_hIcon);
	}
	else
	{
		CDialogEx::OnPaint();
	}
}

// The system calls this function to obtain the cursor to display while the user drags
//  the minimized window.
HCURSOR CFireWallMini1Dlg::OnQueryDragIcon()
{
	return static_cast<HCURSOR>(m_hIcon);
}


void CFireWallMini1Dlg::OnBnClickedBtnStart()
{
	// Kiểm tra đã chọn adapter mạng chưa
	int nIndex = m_cbAdapter.GetCurSel();
	if (nIndex <= 0 || nIndex >= m_adapterNames.size()) {
		MessageBox(_T("Vui lòng chọn Adapter!"), _T("Lỗi"), MB_ICONWARNING);
		return;
	}

	// Lấy tên adapter thực (ví dụ: \Device\NPF_{...})
	std::string adapterName = m_adapterNames[nIndex];

	CString wName(adapterName.c_str());
	DEBUG_LOG(L"[START] Trying to open adapter: %s", (LPCTSTR)wName);

	char errbuf[PCAP_ERRBUF_SIZE];

	// 1. Mở Adapter (Promiscuous mode, timeout 1000ms)
		// Sử dụng pcap_open_live
	m_adhandle = pcap_open_live(adapterName.c_str(), 65536, 0, 10, errbuf);

	if (m_adhandle == nullptr) {
		DEBUG_LOG(L"[ERROR] pcap_open_live failed: %S", errbuf);
		MessageBox(_T("Không thể mở adapter. Hãy chạy với quyền Admin!"), _T("Lỗi"), MB_ICONERROR);
		return;
	}

	int linkType = pcap_datalink(m_adhandle);
	if (linkType != 1) {
		CString strWarn;
		strWarn.Format(_T("Cảnh báo: Adapter này có LinkType = %d (không phải Ethernet chuẩn 1).\nViệc phân tích header (offset 14) có thể bị sai!"), linkType);
		MessageBox(strWarn, _T("Cảnh báo"), MB_ICONWARNING);
	}

	m_debugPacketCount = 0; // Reset biến đếm gói debug
	// 2. Cập nhật UI
	m_isCapturing = true;
	m_btnStart.EnableWindow(FALSE);
	m_btnStop.EnableWindow(TRUE);
	m_cbAdapter.EnableWindow(FALSE);
	m_btnStart.SetWindowText(_T("Running..."));

	// 3. Khởi chạy Worker Thread
	DEBUG_LOG(L"[INFO] Starting Capture Thread...");
	m_pCaptureThread = AfxBeginThread(CaptureThreadFunc, this);
}


void CFireWallMini1Dlg::OnBnClickedBtnStop()
{
	// Chỉ xử lý nếu đang capture
	if (m_isCapturing) {
		m_isCapturing = false; // Đặt cờ này trước để PacketHandler ngừng xử lý ngay lập tức

		if (m_adhandle) {
			// Log để debug xem quy trình stop có chạy không
			DEBUG_LOG(L"[STOP] Stopping capture...");

			// pcap_breakloop an toàn hơn khi gọi từ thread khác, 
			// nhưng nếu loop đã chết (do lỗi -1) thì dòng này có thể thừa nhưng không sao.
			pcap_breakloop(m_adhandle);

			// Đợi một chút để Thread kịp thoát (hack nhỏ để tránh race condition)
			Sleep(100);

			pcap_close(m_adhandle);
			m_adhandle = nullptr;
			DEBUG_LOG(L"[STOP] Adapter closed.");
		}

		// Reset giao diện
		m_btnStart.EnableWindow(TRUE);
		m_btnStart.SetWindowText(_T("Start Capture"));
		m_btnStop.EnableWindow(FALSE);
		m_btnStop.SetWindowText(_T("Stopped"));
		m_cbAdapter.EnableWindow(TRUE);
	}
}

void CFireWallMini1Dlg::OnBnClickedBtnClear()
{
	m_listLog.DeleteAllItems();
	m_cntTotal = m_cntTcp = m_cntUdp = m_cntIcmp = 0;

	m_strTotal.SetWindowText(_T("0"));
	m_strTcp.SetWindowText(_T("0"));
	m_strUdp.SetWindowText(_T("0"));
	m_strIcmp.SetWindowText(_T("0"));
	m_strRowCount.SetWindowText(_T("0"));
}



// Worker Thread function
UINT CFireWallMini1Dlg::CaptureThreadFunc(LPVOID pParam)
{
	CFireWallMini1Dlg* pDlg = (CFireWallMini1Dlg*)pParam;

	DEBUG_LOG(L"[THREAD] Capture Thread Started. Handle: %p", pDlg->m_adhandle);

	if (pDlg->m_adhandle) {
		// pcap_loop trả về: 0 (hết gói), -1 (lỗi), -2 (breakloop)
		int ret = pcap_loop(pDlg->m_adhandle, 0, PacketHandler, (u_char*)pDlg);

		DEBUG_LOG(L"[THREAD] pcap_loop finished. Return Code: %d", ret);

		if (ret == -1) {
			// Nếu lỗi, in chi tiết lỗi từ driver
			DEBUG_LOG(L"[THREAD] Error Detail: %S", pcap_geterr(pDlg->m_adhandle));
		}
	}
	else {
		DEBUG_LOG(L"[THREAD] Error: Handle is NULL");
	}

	DEBUG_LOG(L"[THREAD] Capture Thread Exiting...");
	return 0;
}

// Hàm xử lý mỗi gói bắt được
void CFireWallMini1Dlg::PacketHandler(u_char* param, const struct pcap_pkthdr* header, const u_char* pkt_data)
{
	CFireWallMini1Dlg* pDlg = (CFireWallMini1Dlg*)param;
	if (!pDlg->m_isCapturing) return;

	// --- SỬA LẠI PHẦN LOGGING ---
	// Tăng biến đếm thành viên (đã được reset khi bấm Start)
	pDlg->m_debugPacketCount++;

	// Chỉ log 50 gói đầu tiên của phiên chạy hiện tại
	bool shouldLog = (pDlg->m_debugPacketCount < 50);

	if (shouldLog) {
		DEBUG_LOG(L"[PACKET #%d] Captured Len: %d", pDlg->m_debugPacketCount, header->len);
	}
	// ----------------------------

	// --- KIỂM TRA ĐỘ DÀI GÓI TIN ---
	// Tránh đọc quá vùng nhớ nếu gói tin quá ngắn
	if (header->len < 14) return; // Không đủ header Ethernet

	// 1. Parse Ethernet Header (14 bytes)
	IpHeader* ipHeader = (IpHeader*)(pkt_data + 14);

	// Kiểm tra version IP (Chỉ xử lý IPv4 - 4 bits đầu tiên là 4)
	// ipHeader->ver_ihl là 1 byte: VVVV IIII. Lấy 4 bit đầu.
	int version = (ipHeader->ver_ihl >> 4);
	if (version != 4) {
		// Nếu không phải IPv4, bỏ qua để tránh rác
		return;
	}

	// 2. Parse IP Addresses
	struct in_addr source, dest;
	memcpy(&source, ipHeader->saddr, 4);
	memcpy(&dest, ipHeader->daddr, 4);

	char strSrcBuffer[INET_ADDRSTRLEN];
	char strDstBuffer[INET_ADDRSTRLEN];
	inet_ntop(AF_INET, &source, strSrcBuffer, INET_ADDRSTRLEN);
	inet_ntop(AF_INET, &dest, strDstBuffer, INET_ADDRSTRLEN);

	CString srcIP(strSrcBuffer);
	CString dstIP(strDstBuffer);

	int protocol = ipHeader->proto;
	int srcPort = 0, dstPort = 0;
	CString strProtocol = _T("OTHER");

	// 3. Parse Protocol
	if (protocol == IPPROTO_TCP) {
		strProtocol = _T("TCP");
		// Tính toán offset header IP thực tế (vì IHL có thể > 5)
		int ipHeaderLen = (ipHeader->ver_ihl & 0x0F) * 4;
		TcpHeader* tcpHeader = (TcpHeader*)(pkt_data + 14 + ipHeaderLen);
		srcPort = ntohs(tcpHeader->sport);
		dstPort = ntohs(tcpHeader->dport);
	}
	else if (protocol == IPPROTO_UDP) {
		strProtocol = _T("UDP");
		int ipHeaderLen = (ipHeader->ver_ihl & 0x0F) * 4;
		UdpHeader* udpHeader = (UdpHeader*)(pkt_data + 14 + ipHeaderLen);
		srcPort = ntohs(udpHeader->sport);
		dstPort = ntohs(udpHeader->dport);
	}
	else if (protocol == IPPROTO_ICMP) {
		strProtocol = _T("ICMP");
	}


	// 4. Match Rule
	CString matchedRule = _T("");
	bool isMatch = false;

	if (strProtocol == _T("UDP")) {
		matchedRule = _T("Rule 1 (All UDP)");
		isMatch = true;
	}
	else if (strProtocol == _T("TCP")) {
		matchedRule = _T("Rule 2 (All TCP)");
		isMatch = true;
	}
	else if (strProtocol == _T("ICMP")) {
		matchedRule = _T("Rule 3 (ICMP - Ping)");
		isMatch = true;
	}

	// 5. Gửi về UI hoặc Log Drop
	if (isMatch) {
		// Log MATCH luôn được hiện (vì số lượng ít hơn nhiều so với RAW)
		DEBUG_LOG(L"[MATCH] Rule: %s | Proto: %s | Src: %s", (LPCTSTR)matchedRule, (LPCTSTR)strProtocol, (LPCTSTR)srcIP);

		LogData* pLog = new LogData;

		// Format Time
		time_t local_tv_sec = header->ts.tv_sec;
		struct tm ltime;
		localtime_s(&ltime, &local_tv_sec);
		char timestr[16];
		strftime(timestr, sizeof timestr, "%H:%M:%S", &ltime);

		pLog->time = CString(timestr);
		pLog->protocol = strProtocol;
		pLog->srcIP = srcIP;
		pLog->srcPort.Format(_T("%d"), srcPort);
		pLog->dstIP = dstIP;
		pLog->dstPort.Format(_T("%d"), dstPort);
		pLog->matchedRule = matchedRule;

		pDlg->PostMessage(WM_UPDATE_LOG, (WPARAM)pLog, 0);
	}

}


LRESULT CFireWallMini1Dlg::OnUpdateLog(WPARAM wParam, LPARAM lParam)
{
	LogData* pLog = (LogData*)wParam;
	if (pLog) {
		// 1. Insert Log vào List Control
		int nIndex = m_listLog.GetItemCount();
		m_listLog.InsertItem(nIndex, pLog->time);
		m_listLog.SetItemText(nIndex, 1, pLog->protocol);
		m_listLog.SetItemText(nIndex, 2, pLog->srcIP);
		m_listLog.SetItemText(nIndex, 3, pLog->srcPort);
		m_listLog.SetItemText(nIndex, 4, pLog->dstIP);
		m_listLog.SetItemText(nIndex, 5, pLog->dstPort);
		m_listLog.SetItemText(nIndex, 6, pLog->matchedRule);

		// Auto scroll xuống dưới cùng
		m_listLog.EnsureVisible(nIndex, FALSE);

		// 2. Cập nhật Counters [cite: 71, 73]
		m_cntTotal++;
		if (pLog->protocol == _T("TCP")) m_cntTcp++;
		else if (pLog->protocol == _T("UDP")) m_cntUdp++;
		else if (pLog->protocol == _T("ICMP")) m_cntIcmp++;

		CString strTmp;
		strTmp.Format(_T("%ld"), m_cntTotal); m_strTotal.SetWindowText(strTmp);
		strTmp.Format(_T("%ld"), m_cntTcp);   m_strTcp.SetWindowText(strTmp);
		strTmp.Format(_T("%ld"), m_cntUdp);   m_strUdp.SetWindowText(strTmp);
		strTmp.Format(_T("%ld"), m_cntIcmp);  m_strIcmp.SetWindowText(strTmp);

		strTmp.Format(_T("%d rows"), nIndex + 1); m_strRowCount.SetWindowText(strTmp);

		// Giải phóng bộ nhớ
		delete pLog;
	}
	return 0;
}