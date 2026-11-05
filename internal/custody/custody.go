package custody

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"evidence-upload/internal/models"

	"github.com/jung-kurt/gofpdf"
)

const (
	pageWidth   = 210.0
	pageHeight  = 297.0
	marginLeft  = 15.0
	marginRight = 15.0
	marginTop   = 15.0
	colWidth    = pageWidth - marginLeft - marginRight
)

// cocMu serializes CoC generation: a manual revoke and the expired-session
// cleanup can otherwise write the same PDF concurrently and corrupt it.
var cocMu sync.Mutex

func GenerateCoC(session *models.Session, analystName, storagePath, version string) (string, error) {
	cocMu.Lock()
	defer cocMu.Unlock()

	folderDir := filepath.Join(storagePath, session.FolderName)
	pdfPath := filepath.Join(folderDir, "CHAIN_OF_CUSTODY.pdf")

	if err := os.MkdirAll(folderDir, 0755); err != nil {
		return "", fmt.Errorf("create case folder: %w", err)
	}

	ipInfo := parseIPInfoFile(folderDir)

	// Sanitize every string that reaches the PDF: runes the embedded fonts
	// cannot render are replaced, so generation never fails on exotic input.
	// Filesystem paths above use the raw values.
	session = session.Clone()
	session.Description = sanitizePDFText(session.Description)
	session.UploaderIP = sanitizePDFText(session.UploaderIP)
	session.TriagePackage = sanitizePDFText(session.TriagePackage)
	for i := range session.UploadedFiles {
		session.UploadedFiles[i].Name = sanitizePDFText(session.UploadedFiles[i].Name)
		session.UploadedFiles[i].Hash = sanitizePDFText(session.UploadedFiles[i].Hash)
	}
	for i := range session.Activity {
		session.Activity[i].Action = sanitizePDFText(session.Activity[i].Action)
		session.Activity[i].IP = sanitizePDFText(session.Activity[i].IP)
		session.Activity[i].UserAgent = sanitizePDFText(session.Activity[i].UserAgent)
		session.Activity[i].Details = sanitizePDFText(session.Activity[i].Details)
	}
	analystName = sanitizePDFText(analystName)
	for k, v := range ipInfo {
		ipInfo[k] = sanitizePDFText(v)
	}

	pdf := gofpdf.New("P", "mm", "A4", "")
	setupFonts(pdf)
	pdf.SetAutoPageBreak(true, marginTop)
	pdf.AddPage()

	drawHeader(pdf, session)
	drawCaseInfo(pdf, session, analystName, ipInfo)
	drawEvidenceItems(pdf, session)
	drawActivityTimeline(pdf, session)
	drawIntegritySection(pdf, session)
	drawSignatureBlock(pdf, analystName)
	drawFooter(pdf, session, version)

	if err := pdf.OutputFileAndClose(pdfPath); err != nil {
		return "", fmt.Errorf("write PDF: %w", err)
	}

	writeCoCStamp(pdfPath)

	return pdfPath, nil
}

func drawHeader(pdf *gofpdf.Fpdf, session *models.Session) {
	pdf.SetFont("DejaVu", "B", 22)
	pdf.SetTextColor(15, 52, 96)
	pdf.CellFormat(colWidth, 12, "CHAIN OF CUSTODY", "", 1, "C", false, 0, "")

	pdf.SetFont("DejaVu", "", 10)
	pdf.SetTextColor(100, 100, 100)
	pdf.CellFormat(colWidth, 6, "Digital Forensic Evidence Collection Record", "", 1, "C", false, 0, "")

	pdf.Ln(2)
	pdf.SetDrawColor(15, 52, 96)
	pdf.SetLineWidth(0.5)
	pdf.Line(marginLeft, pdf.GetY(), pageWidth-marginRight, pdf.GetY())
	pdf.Ln(6)
}

func drawCaseInfo(pdf *gofpdf.Fpdf, session *models.Session, analystName string, ipInfo map[string]string) {
	pdf.SetFont("DejaVu", "B", 12)
	pdf.SetTextColor(15, 52, 96)
	pdf.CellFormat(colWidth, 8, "CASE INFORMATION", "", 1, "L", false, 0, "")
	pdf.Ln(2)

	rows := [][2]string{
		{"Case Description:", session.Description},
		{"Session Token:", session.Token},
		{"Created:", session.CreatedAt.Format("2006-01-02 15:04:05 MST")},
		{"Expires:", session.ExpiresAt.Format("2006-01-02 15:04:05 MST")},
		{"Status:", "REVOKED"},
		{"Analyst:", analystName},
		{"Generated:", time.Now().Format("2006-01-02 15:04:05 MST")},
	}

	pdf.SetFont("DejaVu", "", 10)
	for _, row := range rows {
		pdf.SetTextColor(100, 100, 100)
		pdf.CellFormat(45, 6, row[0], "", 0, "L", false, 0, "")
		pdf.SetTextColor(30, 30, 30)
		pdf.MultiCell(colWidth-45, 6, row[1], "", "L", false)
		pdf.Ln(1)
	}

	pdf.Ln(2)
	pdf.SetFont("DejaVu", "B", 12)
	pdf.SetTextColor(15, 52, 96)
	pdf.CellFormat(colWidth, 8, "COLLECTOR IP INFORMATION", "", 1, "L", false, 0, "")
	pdf.Ln(2)

	pdf.SetFont("DejaVu", "", 10)
	if ipInfo != nil {
		firstOf := func(vals ...string) string {
			for _, v := range vals {
				if v != "" {
					return v
				}
			}
			return ""
		}
		ipRows := [][2]string{
			{"Uploader IP (server view):", firstOf(ipInfo["Uploader IP (as seen by server)"], ipInfo["Local IP"])},
			{"Uploader Local IP:", ipInfo["Uploader Local IP"]},
			{"Server Public IP:", firstOf(ipInfo["Server Public IP"], ipInfo["Public Internet IP"])},
			{"Server LAN IP:", ipInfo["Server LAN IP"]},
			{"Forwarded For:", ipInfo["Forwarded For"]},
			{"Real IP Header:", ipInfo["Real IP Header"]},
			{"Protocol:", ipInfo["Protocol"]},
			{"User Agent:", ipInfo["User Agent"]},
		}
		for _, row := range ipRows {
			if row[1] == "" || row[1] == "N/A" {
				continue
			}
			pdf.SetTextColor(100, 100, 100)
			pdf.CellFormat(45, 6, row[0], "", 0, "L", false, 0, "")
			pdf.SetTextColor(30, 30, 30)
			pdf.MultiCell(colWidth-45, 6, row[1], "", "L", false)
			pdf.Ln(1)
		}
	} else {
		pdf.SetTextColor(100, 100, 100)
		pdf.CellFormat(45, 6, "Collector IP:", "", 0, "L", false, 0, "")
		pdf.SetTextColor(30, 30, 30)
		ip := session.UploaderIP
		if ip == "" {
			ip = "Unknown"
		}
		pdf.MultiCell(colWidth-45, 6, ip, "", "L", false)
		pdf.Ln(1)
	}

	pdf.Ln(4)
}

func drawEvidenceItems(pdf *gofpdf.Fpdf, session *models.Session) {
	pdf.SetFont("DejaVu", "B", 12)
	pdf.SetTextColor(15, 52, 96)
	pdf.CellFormat(colWidth, 8, "EVIDENCE ITEMS", "", 1, "L", false, 0, "")
	pdf.Ln(2)

	if len(session.UploadedFiles) == 0 {
		pdf.SetFont("DejaVu", "I", 10)
		pdf.SetTextColor(100, 100, 100)
		pdf.CellFormat(colWidth, 6, "No files uploaded.", "", 1, "L", false, 0, "")
		pdf.Ln(4)
		return
	}

	pdf.SetFont("DejaVu", "B", 9)
	pdf.SetFillColor(15, 52, 96)
	pdf.SetTextColor(255, 255, 255)
	pdf.CellFormat(60, 7, "Filename", "1", 0, "L", true, 0, "")
	pdf.CellFormat(25, 7, "Size", "1", 0, "R", true, 0, "")
	pdf.CellFormat(95, 7, "SHA-256 Hash", "1", 1, "L", true, 0, "")

	pdf.SetFont("DejaVu", "", 8)
	pdf.SetTextColor(30, 30, 30)
	for i, f := range session.UploadedFiles {
		fill := i%2 == 0
		if fill {
			pdf.SetFillColor(240, 244, 248)
		}
		pdf.CellFormat(60, 6, truncate(f.Name, 35), "1", 0, "L", fill, 0, "")
		pdf.CellFormat(25, 6, humanSize(f.Size), "1", 0, "R", fill, 0, "")
		hashDisplay := f.Hash
		if r := []rune(hashDisplay); len(r) > 40 {
			hashDisplay = string(r[:40]) + "..."
		}
		pdf.CellFormat(95, 6, hashDisplay, "1", 1, "L", fill, 0, "")
	}

	pdf.Ln(4)
}

func drawActivityTimeline(pdf *gofpdf.Fpdf, session *models.Session) {
	pdf.SetFont("DejaVu", "B", 12)
	pdf.SetTextColor(15, 52, 96)
	pdf.CellFormat(colWidth, 8, "ACTIVITY TIMELINE", "", 1, "L", false, 0, "")
	pdf.Ln(2)

	if len(session.Activity) == 0 {
		pdf.SetFont("DejaVu", "I", 10)
		pdf.SetTextColor(100, 100, 100)
		pdf.CellFormat(colWidth, 6, "No activity recorded.", "", 1, "L", false, 0, "")
		pdf.Ln(4)
		return
	}

	pdf.SetFont("DejaVu", "B", 9)
	pdf.SetFillColor(15, 52, 96)
	pdf.SetTextColor(255, 255, 255)
	pdf.CellFormat(40, 7, "Timestamp", "1", 0, "L", true, 0, "")
	pdf.CellFormat(30, 7, "Action", "1", 0, "L", true, 0, "")
	pdf.CellFormat(30, 7, "IP Address", "1", 0, "L", true, 0, "")
	pdf.CellFormat(80, 7, "Details", "1", 1, "L", true, 0, "")

	pdf.SetFont("DejaVu", "", 8)
	pdf.SetTextColor(30, 30, 30)
	for i, a := range session.Activity {
		fill := i%2 == 0
		if fill {
			pdf.SetFillColor(240, 244, 248)
		}
		pdf.CellFormat(40, 6, a.Timestamp.Format("2006-01-02 15:04:05"), "1", 0, "L", fill, 0, "")
		pdf.CellFormat(30, 6, a.Action, "1", 0, "L", fill, 0, "")
		pdf.CellFormat(30, 6, a.IP, "1", 0, "L", fill, 0, "")
		details := a.Details
		if details == "" {
			details = a.UserAgent
		}
		pdf.CellFormat(80, 6, truncate(details, 50), "1", 1, "L", fill, 0, "")
	}

	pdf.Ln(4)
}

func drawIntegritySection(pdf *gofpdf.Fpdf, session *models.Session) {
	pdf.SetFont("DejaVu", "B", 12)
	pdf.SetTextColor(15, 52, 96)
	pdf.CellFormat(colWidth, 8, "INTEGRITY VERIFICATION", "", 1, "L", false, 0, "")
	pdf.Ln(2)

	pdf.SetFont("DejaVu", "", 10)
	pdf.SetTextColor(30, 30, 30)

	pdf.CellFormat(45, 6, "Total Files:", "", 0, "L", false, 0, "")
	pdf.CellFormat(colWidth-45, 6, fmt.Sprintf("%d", len(session.UploadedFiles)), "", 1, "L", false, 0, "")

	pdf.CellFormat(45, 6, "Total Size:", "", 0, "L", false, 0, "")
	pdf.CellFormat(colWidth-45, 6, humanSize(session.TotalSize), "", 1, "L", false, 0, "")

	pdf.CellFormat(45, 6, "HMAC Token:", "", 0, "L", false, 0, "")
	pdf.SetFont("DejaVuMono", "", 8)
	pdf.CellFormat(colWidth-45, 6, session.Token, "", 1, "L", false, 0, "")

	pdf.SetFont("DejaVu", "", 10)
	pdf.CellFormat(45, 6, "Session Secret:", "", 0, "L", false, 0, "")
	pdf.SetFont("DejaVuMono", "", 8)
	pdf.CellFormat(colWidth-45, 6, session.Secret, "", 1, "L", false, 0, "")

	pdf.SetFont("DejaVu", "I", 8)
	pdf.SetTextColor(100, 100, 100)
	pdf.MultiCell(colWidth, 5, "Each evidence file has an accompanying .sha256 sidecar file for independent integrity verification. Use 'sha256sum -c' to verify.", "", "L", false)

	pdf.Ln(4)
}

func drawSignatureBlock(pdf *gofpdf.Fpdf, analystName string) {
	pdf.SetFont("DejaVu", "B", 12)
	pdf.SetTextColor(15, 52, 96)
	pdf.CellFormat(colWidth, 8, "CHAIN OF CUSTODY CERTIFICATION", "", 1, "L", false, 0, "")
	pdf.Ln(2)

	pdf.SetFont("DejaVu", "", 9)
	pdf.SetTextColor(30, 30, 30)
	pdf.MultiCell(colWidth, 5, "I certify that the above evidence items were collected, handled, and stored in accordance with established forensic procedures. The evidence integrity has been verified through SHA-256 cryptographic hashing.", "", "L", false)
	pdf.Ln(8)

	pdf.SetFont("DejaVu", "", 10)
	pdf.CellFormat(25, 6, "Analyst:", "", 0, "L", false, 0, "")
	pdf.CellFormat(70, 6, analystName, "", 0, "L", false, 0, "")
	pdf.CellFormat(20, 6, "Date:", "", 0, "L", false, 0, "")
	pdf.CellFormat(55, 6, time.Now().Format("2006-01-02"), "", 1, "L", false, 0, "")

	pdf.Ln(10)
	pdf.SetDrawColor(30, 30, 30)
	pdf.SetLineWidth(0.3)
	pdf.Line(marginLeft, pdf.GetY(), marginLeft+70, pdf.GetY())
	pdf.Line(pageWidth-marginRight-70, pdf.GetY(), pageWidth-marginRight, pdf.GetY())
	pdf.Ln(2)

	pdf.SetFont("DejaVu", "", 8)
	pdf.SetTextColor(100, 100, 100)
	pdf.CellFormat(70, 5, "Analyst Signature", "", 0, "L", false, 0, "")
	pdf.CellFormat(pageWidth-marginLeft-marginRight-140, 5, "", "", 0, "C", false, 0, "")
	pdf.CellFormat(70, 5, "Date", "", 1, "R", false, 0, "")
}

func drawFooter(pdf *gofpdf.Fpdf, session *models.Session, version string) {
	pdf.Ln(8)
	pdf.SetDrawColor(15, 52, 96)
	pdf.SetLineWidth(0.3)
	pdf.Line(marginLeft, pdf.GetY(), pageWidth-marginRight, pdf.GetY())
	pdf.Ln(3)

	pdf.SetFont("DejaVu", "I", 7)
	pdf.SetTextColor(130, 130, 130)
	tokenShort := session.Token
	if len(tokenShort) > 16 {
		tokenShort = tokenShort[:16]
	}
	pdf.MultiCell(colWidth, 4, fmt.Sprintf(
		"Generated by Evidence Upload v%s | Case: %s | Token: %s | This document is part of the forensic evidence chain.",
		version, session.Description, tokenShort+"...",
	), "", "C", false)
}

func parseIPInfoFile(caseFolder string) map[string]string {
	entries, err := os.ReadDir(caseFolder)
	if err != nil {
		return nil
	}

	var ipFile string
	for _, entry := range entries {
		if !entry.IsDir() && strings.HasPrefix(entry.Name(), "ip_detection_") && strings.HasSuffix(entry.Name(), ".txt") {
			ipFile = entry.Name()
			break
		}
	}
	if ipFile == "" {
		return nil
	}

	data, err := os.ReadFile(filepath.Join(caseFolder, ipFile))
	if err != nil {
		return nil
	}

	result := make(map[string]string)
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "=") || strings.HasPrefix(line, "IP Detection") {
			continue
		}
		parts := strings.SplitN(line, ": ", 2)
		if len(parts) == 2 {
			key := strings.TrimSpace(parts[0])
			val := strings.TrimSpace(parts[1])
			result[key] = val
		}
	}

	if len(result) == 0 {
		return nil
	}
	return result
}

func writeCoCStamp(pdfPath string) {
	data, err := os.ReadFile(pdfPath)
	if err != nil {
		return
	}
	hash := sha256.Sum256(data)
	hexHash := hex.EncodeToString(hash[:])
	stampPath := pdfPath + ".sha256"
	content := fmt.Sprintf("%s  %s\n", hexHash, filepath.Base(pdfPath))
	os.WriteFile(stampPath, []byte(content), 0644)
}

func humanSize(bytes int64) string {
	const (
		KB = 1024
		MB = 1024 * KB
		GB = 1024 * MB
	)
	switch {
	case bytes >= GB:
		return fmt.Sprintf("%.2f GB", float64(bytes)/float64(GB))
	case bytes >= MB:
		return fmt.Sprintf("%.1f MB", float64(bytes)/float64(MB))
	case bytes >= KB:
		return fmt.Sprintf("%.1f KB", float64(bytes)/float64(KB))
	default:
		return fmt.Sprintf("%d B", bytes)
	}
}

func truncate(s string, maxLen int) string {
	s = strings.TrimSpace(s)
	r := []rune(s)
	if len(r) <= maxLen {
		return s
	}
	return string(r[:maxLen-3]) + "..."
}
