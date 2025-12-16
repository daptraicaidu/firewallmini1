
// FireWallMini1Dlg.cpp : implementation file
//

#include "pch.h"
#include "framework.h"
#include "FireWallMini1.h"
#include "FireWallMini1Dlg.h"
#include "afxdialogex.h"

#ifdef _DEBUG
#define new DEBUG_NEW
#endif


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
	
	// Cấu hình ComboBox Adapter
	m_cbAdapter.AddString(_T("-- Chọn adapter --"));
	m_cbAdapter.AddString(_T("Demo: Npcap Loopback"));
	m_cbAdapter.SetCurSel(0);

	// Hiển thị danh sách Rule đang kích hoạt
	CString strRulesContent = _T("Danh sách Rule kích hoạt:\n")
		_T("-----------------------------\n")
		_T("Rule 1: Log mọi gói UDP\n")
		_T("Rule 2: Log mọi TCP đến port 80\n")
		_T("Rule 3: Log gói từ IP 192.168.1.10");

	m_staticRules.SetWindowText(strRulesContent);

	// Cấu hình List Control
	m_listLog.SetExtendedStyle(LVS_EX_FULLROWSELECT | LVS_EX_GRIDLINES);
	m_listLog.InsertColumn(0, _T("Time"), LVCFMT_LEFT, 100);
	m_listLog.InsertColumn(1, _T("Protocol"), LVCFMT_LEFT, 60);
	m_listLog.InsertColumn(2, _T("Src IP"), LVCFMT_LEFT, 120);
	m_listLog.InsertColumn(3, _T("Src Port"), LVCFMT_LEFT, 60);
	m_listLog.InsertColumn(4, _T("Dst IP"), LVCFMT_LEFT, 120);
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
	// Nếu chưa chọn gì (CB_ERR) hoặc chọn dòng đầu tiên ("-- Chọn adapter --")
	if (nIndex == CB_ERR || nIndex == 0)
	{
		MessageBox(_T("Vui lòng chọn một Adapter mạng để bắt đầu!"),
			_T("Lỗi"),
			MB_OK | MB_ICONWARNING);
		return; // Thoát hàm ngay, không chạy tiếp
	}


	m_btnStart.SetWindowText(_T("Running"));
	m_btnStart.EnableWindow(FALSE);

	m_btnStop.SetWindowText(_T("Stop Capture"));
	m_btnStop.EnableWindow(TRUE);


	// TODO: Add your control notification handler code here
}

void CFireWallMini1Dlg::OnBnClickedBtnStop()
{
	m_btnStart.SetWindowText(_T("Start Capture"));
	m_btnStart.EnableWindow(TRUE);

	m_btnStop.SetWindowText(_T("Stopped"));
	m_btnStop.EnableWindow(FALSE);


	// TODO: Add your control notification handler code here
}
