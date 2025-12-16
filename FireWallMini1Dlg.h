
// FireWallMini1Dlg.h : header file
//

#pragma once


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
	DECLARE_MESSAGE_MAP()
public:
	CListCtrl m_listLog;
	CButton m_btnStart;
	CButton m_btnStop;
	CStatic m_strTotal;
	CStatic m_strTcp;
	CStatic m_strUdp;
	CStatic m_strIcmp;
	CComboBox m_cbAdapter;
	CButton m_btnClear;
	CStatic m_strRowCount;
	CStatic m_staticRules;
	afx_msg void OnBnClickedBtnStart();
	afx_msg void OnBnClickedBtnStop();
};
