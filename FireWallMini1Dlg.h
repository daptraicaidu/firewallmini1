
// FireWallMini1Dlg.h : header file
//

#pragma once
#include <vector>
#include <string>

#ifndef _PCAP_H_ // Kiểm tra nếu chưa include pcap.h thì tự định nghĩa
struct pcap;
typedef struct pcap pcap_t;
#endif

// CFireWallMini1Dlg dialog
class CFireWallMini1Dlg : public CDialogEx
{
// Construction
public:
	CFireWallMini1Dlg(CWnd* pParent = nullptr);	// standard constructor

// Dialog Data
#ifdef AFX_DESIGN_TIME
	enum { IDD = IDD_FIREWALLMINI1_DIALOG };
#endif

	protected:
	virtual void DoDataExchange(CDataExchange* pDX);	// DDX/DDV support


// Implementation
protected:
	HICON m_hIcon;

	// Generated message map functions
	virtual BOOL OnInitDialog();
	afx_msg void OnSysCommand(UINT nID, LPARAM lParam);
	afx_msg void OnPaint();
	afx_msg HCURSOR OnQueryDragIcon();
	afx_msg void OnCustomDrawList(NMHDR* pNMHDR, LRESULT* pResult);
	DECLARE_MESSAGE_MAP()

	// Biến quản lý Npcap
	pcap_t* m_adhandle;           // Handle của adapter đang mở
	bool m_isCapturing;           // Cờ trạng thái đang chạy hay dừng
	CWinThread* m_pCaptureThread; // Con trỏ quản lý Thread bắt gói

	// Danh sách tên thiết bị (name) tương ứng với ComboBox
	std::vector<std::string> m_adapterNames;

	// Các biến đếm thống kê
	long m_cntTotal;
	long m_cntTcp;
	long m_cntUdp;
	long m_cntIcmp;
	long m_cntOther;

	unsigned int m_linkHeaderLen; // Độ dài header liên kết (Link Layer)

	// Hàm Worker Thread (static để chạy độc lập)
	static UINT CaptureThreadFunc(LPVOID pParam);

	// Hàm xử lý gói tin (được gọi bởi pcap_loop)
	static void PacketHandler(u_char* param, const struct pcap_pkthdr* header, const u_char* pkt_data);

	// Hàm nhận Message từ Thread để update UI
	afx_msg LRESULT OnUpdateLog(WPARAM wParam, LPARAM lParam);

	// Hàm xóa log (cho nút Clear)
	afx_msg void OnBnClickedBtnClear();

public:
	CListCtrl m_listLog;
	CButton m_btnStart;
	CButton m_btnStop;
	CStatic m_strTotal;
	CStatic m_strTcp;
	CStatic m_strUdp;
	CStatic m_strIcmp;
	CStatic m_strOther;
	CComboBox m_cbAdapter;
	CButton m_btnClear;
	CStatic m_strRowCount;
	CStatic m_staticRules;
	afx_msg void OnBnClickedBtnStart();
	afx_msg void OnBnClickedBtnStop();
};
