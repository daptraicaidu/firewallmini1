
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
	CString size;
	CString info;
	CString matchedRule;
};

struct IcmpHeader {
	unsigned char type; // 8=Request, 0=Reply
	unsigned char code;
	unsigned short checksum;
	unsigned short id;
	unsigned short seq;
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
	, m_linkHeaderLen(0)
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
	ON_NOTIFY(NM_CUSTOMDRAW, IDC_LIST_LOG, &CFireWallMini1Dlg::OnCustomDrawList)
	
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
		_T("Rule 1: Log mọi gói TCP\n")
		_T("Rule 2: Log mọi gói UDP\n")
		_T("Rule 3: Log mọi gói ICMP")
		;

	m_staticRules.SetWindowText(strRulesContent);

	// Cấu hình List Control
	m_listLog.SetExtendedStyle(LVS_EX_FULLROWSELECT | LVS_EX_GRIDLINES);
	m_listLog.InsertColumn(0, _T("No."), LVCFMT_LEFT, 50);
	m_listLog.InsertColumn(1, _T("Time"), LVCFMT_LEFT, 90);
	m_listLog.InsertColumn(2, _T("Protocol"), LVCFMT_LEFT, 60);
	m_listLog.InsertColumn(3, _T("Src IP"), LVCFMT_LEFT, 110);
	m_listLog.InsertColumn(4, _T("Src Port"), LVCFMT_LEFT, 60);
	m_listLog.InsertColumn(5, _T("Dst IP"), LVCFMT_LEFT, 110);
	m_listLog.InsertColumn(6, _T("Dst Port"), LVCFMT_LEFT, 60);
	m_listLog.InsertColumn(7, _T("Size"), LVCFMT_LEFT, 60);
	m_listLog.InsertColumn(8, _T("Info"), LVCFMT_LEFT, 200);
	m_listLog.InsertColumn(9, _T("Matched Rule"), LVCFMT_LEFT, 90);


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

	CString strFriendlyName;
	m_cbAdapter.GetLBText(nIndex, strFriendlyName);
	DEBUG_LOG(L"[CHECK] Ban chon: %s", (LPCTSTR)strFriendlyName);
	DEBUG_LOG(L"[START] Trying to open adapter: %s", (LPCTSTR)wName);

	char errbuf[PCAP_ERRBUF_SIZE];

	// 1. Mở Adapter (Promiscuous mode, timeout 1000ms)
		// Sử dụng pcap_open_live
	m_adhandle = pcap_open_live(adapterName.c_str(), 65536, 1, 1000, errbuf);

	if (m_adhandle == nullptr) {
		DEBUG_LOG(L"[ERROR] pcap_open_live failed: %S", errbuf);
		MessageBox(_T("Không thể mở adapter. Hãy chạy với quyền Admin!"), _T("Lỗi"), MB_ICONERROR);
		return;
	}

	int linkType = pcap_datalink(m_adhandle);
	if (linkType == 1) {
		// DLT_EN10MB: Ethernet chuẩn (Card Intel, Wi-Fi, Dây)
		m_linkHeaderLen = 14;
		DEBUG_LOG(L"[INFO] Phat hien Ethernet Link. Offset = 14");
	}
	else if (linkType == 0) {
		// DLT_NULL: Loopback (Localhost)
		m_linkHeaderLen = 4;
		DEBUG_LOG(L"[INFO] Phat hien Loopback Link. Offset = 4");
	}
	else {
		// Trường hợp lạ khác
		CString strWarn;
		strWarn.Format(_T("LinkType la %d (khong phai 1 hoac 0). Chuong trinh co the chay sai!"), linkType);
		MessageBox(strWarn, _T("Canh bao"), MB_ICONWARNING);
		m_linkHeaderLen = 14;
	}

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

	DEBUG_LOG(L"[THREAD] Thread bat dau chay voi che do: pcap_next_ex (Polling)");

	if (!pDlg->m_adhandle) {
		DEBUG_LOG(L"[ERROR] Handle bi NULL, thread thoat!");
		return 0;
	}

	struct pcap_pkthdr* header;
	const u_char* pkt_data;
	int res;

	while (pDlg->m_isCapturing) {

		res = pcap_next_ex(pDlg->m_adhandle, &header, &pkt_data);

		if (res == 1) {
			// DEBUG_LOG(L"[RAW] Got packet len: %d", header->len); //spam logs
			PacketHandler((u_char*)pDlg, header, pkt_data);
		}
		else if (res == 0) {
			 DEBUG_LOG(L"[WAIT] Dang cho goi tin..."); 
			continue;
		}
		else if (res == -1) {
			DEBUG_LOG(L"[ERROR] Loi pcap_next_ex: %S", pcap_geterr(pDlg->m_adhandle));
			break; 
		}
		else if (res == -2) {
			DEBUG_LOG(L"[INFO] Adapter bao EOF");
			break;
		}
	}

	DEBUG_LOG(L"[THREAD] Thread ket thuc.");
	return 0;
}

// Hàm xử lý mỗi gói bắt được
void CFireWallMini1Dlg::PacketHandler(u_char* param, const struct pcap_pkthdr* header, const u_char* pkt_data)
{
	CFireWallMini1Dlg* pDlg = (CFireWallMini1Dlg*)param;

	//DEBUG_LOG(L">>> Xu ly goi tin dai: %d bytes", header->len);

	if (!pDlg->m_isCapturing) return;

	// --- KIỂM TRA ĐỘ DÀI GÓI TIN ---
	// Tránh đọc quá vùng nhớ nếu gói tin quá ngắn
	if (header->len < pDlg->m_linkHeaderLen) return;

	// 1. Parse Ethernet Header (14 bytes)
	IpHeader* ipHeader = (IpHeader*)(pkt_data + pDlg->m_linkHeaderLen);

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
	CString strInfo = _T("");

	// 3. Parse Protocol
	if (protocol == IPPROTO_TCP) {
		strProtocol = _T("TCP");
		int ipHeaderLen = (ipHeader->ver_ihl & 0x0F) * 4;
		TcpHeader* tcpHeader = (TcpHeader*)(pkt_data + pDlg->m_linkHeaderLen + ipHeaderLen);
		srcPort = ntohs(tcpHeader->sport);
		dstPort = ntohs(tcpHeader->dport);

		// --- XỬ LÝ INFO TCP (Đọc cờ) ---
		// Cờ nằm trong byte 'flags'
		if (tcpHeader->flags & 0x02) strInfo += _T("[SYN] ");
		if (tcpHeader->flags & 0x10) strInfo += _T("[ACK] ");
		if (tcpHeader->flags & 0x01) strInfo += _T("[FIN] ");
		if (tcpHeader->flags & 0x04) strInfo += _T("[RST] ");
		if (tcpHeader->flags & 0x08) strInfo += _T("[PSH] ");

		// Thêm Seq number cho ngầu (Optional)
		CString strSeq;
		strSeq.Format(_T("Seq=%u"), ntohl(tcpHeader->seq));
		strInfo += strSeq;
	}
	else if (protocol == IPPROTO_UDP) {
		strProtocol = _T("UDP");
		int ipHeaderLen = (ipHeader->ver_ihl & 0x0F) * 4;
		UdpHeader* udpHeader = (UdpHeader*)(pkt_data + pDlg->m_linkHeaderLen + ipHeaderLen);
		srcPort = ntohs(udpHeader->sport);
		dstPort = ntohs(udpHeader->dport);

		// --- XỬ LÝ INFO UDP ---
		strInfo.Format(_T("Len=%d"), ntohs(udpHeader->len));
	}
	else if (protocol == IPPROTO_ICMP) {
		strProtocol = _T("ICMP");
		int ipHeaderLen = (ipHeader->ver_ihl & 0x0F) * 4;

		// Ép kiểu sang IcmpHeader
		IcmpHeader* icmpHeader = (IcmpHeader*)(pkt_data + pDlg->m_linkHeaderLen + ipHeaderLen);

		// --- XỬ LÝ INFO ICMP ---
		if (icmpHeader->type == 8) strInfo = _T("Echo (Ping) Request");
		else if (icmpHeader->type == 0) strInfo = _T("Echo (Ping) Reply");
		else if (icmpHeader->type == 3) strInfo = _T("Destination Unreachable");
		else strInfo.Format(_T("Type=%d, Code=%d"), icmpHeader->type, icmpHeader->code);
	}


	// 4. Match Rule
	CString matchedRule = _T("");
	bool isMatch = false;

	if (strProtocol == _T("TCP")) {
		matchedRule = _T("Rule 1");
		isMatch = true;
	}
	else if (strProtocol == _T("UDP")) {
		matchedRule = _T("Rule 2");
		isMatch = true;
	}
	else if (strProtocol == _T("ICMP")) {
		matchedRule = _T("Rule 3");
		isMatch = true;
	}

	// 5. Gửi về UI hoặc Log Drop
	if (isMatch) {
		// Log MATCH luôn được hiện (vì số lượng ít hơn nhiều so với RAW)
		//DEBUG_LOG(L"[MATCH] Rule: %s | Proto: %s | Src: %s", (LPCTSTR)matchedRule, (LPCTSTR)strProtocol, (LPCTSTR)srcIP);

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
		pLog->size.Format(_T("%d"), header->len);
		pLog->info = strInfo;
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
		CString strNo;
		strNo.Format(_T("%d"), nIndex + 1);
		m_listLog.InsertItem(nIndex, strNo);
		m_listLog.SetItemText(nIndex, 1, pLog->time);       
		m_listLog.SetItemText(nIndex, 2, pLog->protocol);    
		m_listLog.SetItemText(nIndex, 3, pLog->srcIP);       
		m_listLog.SetItemText(nIndex, 4, pLog->srcPort);    
		m_listLog.SetItemText(nIndex, 5, pLog->dstIP);      
		m_listLog.SetItemText(nIndex, 6, pLog->dstPort);   
		m_listLog.SetItemText(nIndex, 7, pLog->size); 
		m_listLog.SetItemText(nIndex, 8, pLog->info);
		m_listLog.SetItemText(nIndex, 9, pLog->matchedRule);

		// Auto scroll xuống dưới cùng
		m_listLog.EnsureVisible(nIndex, FALSE);

		// 2. Cập nhật Counters 
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


// Custom Draw để tô màu nền từng dòng trong List Control
void CFireWallMini1Dlg::OnCustomDrawList(NMHDR* pNMHDR, LRESULT* pResult)
{
	NMLVCUSTOMDRAW* pLVCD = reinterpret_cast<NMLVCUSTOMDRAW*>(pNMHDR);

	// Mặc định trả về Default để Windows tự vẽ các bước tiếp theo
	*pResult = CDRF_DODEFAULT;

	// Giai đoạn 1: Chuẩn bị vẽ (Pre-Paint) -> Yêu cầu thông báo khi vẽ từng dòng (Item)
	if (pLVCD->nmcd.dwDrawStage == CDDS_PREPAINT) {
		*pResult = CDRF_NOTIFYITEMDRAW;
	}
	// Giai đoạn 2: Chuẩn bị vẽ một dòng cụ thể (Item Pre-Paint)
	else if (pLVCD->nmcd.dwDrawStage == CDDS_ITEMPREPAINT) {

		// Lấy số thứ tự dòng đang vẽ
		int nRow = (int)pLVCD->nmcd.dwItemSpec;

		// Lấy nội dung cột Protocol (Cột số 2 - Vì cột 0 là No, cột 1 là Time)
		// Lưu ý: Nếu cột Protocol của bạn ở vị trí khác, hãy sửa số 2
		CString strProtocol = m_listLog.GetItemText(nRow, 2);

		// --- XỬ LÝ TÔ MÀU NỀN (Background Color) ---

		if (strProtocol.Find(_T("TCP")) != -1) {
			// Màu Xanh Lá Nhạt (RGB: 220, 255, 220)
			pLVCD->clrTextBk = RGB(220, 255, 220);
		}
		else if (strProtocol.Find(_T("UDP")) != -1) {
			// Màu Xanh Dương Nhạt (RGB: 220, 240, 255)
			pLVCD->clrTextBk = RGB(220, 240, 255);
		}
		else if (strProtocol.Find(_T("ICMP")) != -1) {
			// Màu Vàng Nhạt (RGB: 255, 255, 220)
			pLVCD->clrTextBk = RGB(255, 255, 220);
		}
		else {
			// Màu trắng mặc định cho các loại khác
			pLVCD->clrTextBk = RGB(255, 255, 255);
		}

		// Báo cho Windows biết là ta đã đổi font/màu rồi
		*pResult = CDRF_NEWFONT;
	}
}