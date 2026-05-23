import React, { useEffect, useState, useRef } from 'react';
import { useParams, Link } from 'react-router-dom';
import { ShieldAlert, AlertTriangle, Info, ChevronDown, ChevronUp, Database, FileText, Smartphone, HardDrive, ArrowLeft, Download } from 'lucide-react';
import jsPDF from 'jspdf';
import autoTable from 'jspdf-autotable';
import { api } from '../api/client';
import type { SecurityReport, Finding } from '../api/client';
import { PieChart, Pie, Cell, ResponsiveContainer, Tooltip } from 'recharts';

export default function ReportPage() {
  const { scanId } = useParams<{ scanId: string }>();
  const [report, setReport] = useState<SecurityReport | null>(null);
  const [isLoading, setIsLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [expandedFindings, setExpandedFindings] = useState<Set<string>>(new Set());
  const reportRef = useRef<HTMLDivElement>(null);
  const [isExporting, setIsExporting] = useState(false);

  useEffect(() => {
    const fetchReport = async () => {
      if (!scanId) return;
      try {
        const response = await api.get(`/scans/${scanId}/report`);
        setReport(response.data);
      } catch (err: any) {
        setError(err.response?.data?.detail || "Failed to load report");
      } finally {
        setIsLoading(false);
      }
    };
    fetchReport();
  }, [scanId]);

  if (isLoading) {
    return <div className="flex items-center justify-center h-full text-slate-500 animate-pulse">Loading report data...</div>;
  }

  if (error || !report) {
    return (
      <div className="bg-red-50 text-red-500 p-6 rounded-xl border border-red-200">
        <h2 className="text-lg font-bold mb-2">Error Loading Report</h2>
        <p>{error || "Report not found."}</p>
      </div>
    );
  }

  const getRiskColor = (score: number) => {
    if (score >= 80) return 'text-red-500 border-red-500 bg-red-50';
    if (score >= 60) return 'text-orange-500 border-orange-500 bg-orange-50';
    if (score >= 40) return 'text-yellow-500 border-yellow-500 bg-yellow-50';
    return 'text-green-500 border-green-500 bg-green-50';
  };

  const severityColors = {
    critical: '#ef4444', // red-500
    high: '#f97316',     // orange-500
    medium: '#eab308',   // yellow-500
    low: '#3b82f6',      // blue-500
    info: '#94a3b8'      // slate-400
  };

  const severityData = [
    { name: 'Critical', value: report.severity_counts.critical, color: severityColors.critical },
    { name: 'High', value: report.severity_counts.high, color: severityColors.high },
    { name: 'Medium', value: report.severity_counts.medium, color: severityColors.medium },
    { name: 'Low', value: report.severity_counts.low, color: severityColors.low },
  ].filter(d => d.value > 0);

  const toggleFinding = (id: string) => {
    const next = new Set(expandedFindings);
    if (next.has(id)) next.delete(id);
    else next.add(id);
    setExpandedFindings(next);
  };

  const handleExportPDF = () => {
    if (!report) return;
    setIsExporting(true);
    
    setTimeout(() => {
      try {
        const doc = new jsPDF();
        const appName = report.static_analysis?.app_name || report.package_name || 'Unknown Package';
        
        // Header
        doc.setFontSize(22);
        doc.setTextColor(30, 41, 59); // slate-800
        doc.text("Security Report", 14, 22);
        
        doc.setFontSize(11);
        doc.setTextColor(100, 116, 139); // slate-500
        doc.text(`${appName} • Scan ID: ${report.scan_id}`, 14, 30);
        
        doc.setFontSize(10);
        doc.text(`Analysed At: ${report.analysed_at ? new Date(report.analysed_at).toLocaleString() : 'N/A'}`, 14, 36);

        // Overall Score
        doc.setFontSize(14);
        doc.setTextColor(30, 41, 59);
        doc.text(`Overall Risk Score: ${report.risk_score} / 100`, 14, 50);
        doc.text(`Risk Level: ${(report.risk_level || 'UNKNOWN').replace('_', ' ')}`, 14, 58);
        
        // Severity Counts
        doc.setFontSize(12);
        doc.text(`Critical: ${report.severity_counts?.critical || 0} | High: ${report.severity_counts?.high || 0} | Medium: ${report.severity_counts?.medium || 0} | Low: ${report.severity_counts?.low || 0}`, 14, 68);

        // Table Data
        const tableBody = allFindings.map(f => [
          f.severity,
          f.rule_name,
          `${f.storage_area} - ${f.file_path.split('/').pop()}`,
          f.description
        ]);

        autoTable(doc, {
          startY: 80,
          head: [['Severity', 'Rule', 'Location', 'Description']],
          body: tableBody,
          styles: { fontSize: 9 },
          headStyles: { fillColor: [30, 41, 59] }, // slate-800
          didParseCell: function(data) {
            if (data.section === 'body' && data.column.index === 0) {
              const sev = data.cell.raw as string;
              if (sev === 'CRITICAL') data.cell.styles.textColor = [239, 68, 68];
              else if (sev === 'HIGH') data.cell.styles.textColor = [249, 115, 22];
              else if (sev === 'MEDIUM') data.cell.styles.textColor = [234, 179, 8];
              else if (sev === 'LOW') data.cell.styles.textColor = [59, 130, 246];
            }
          }
        });

        doc.save(`VaultDex_Report_${report.package_name || report.scan_id}.pdf`);
      } catch (err) {
        console.error("PDF generation failed", err);
      } finally {
        setIsExporting(false);
      }
    }, 100); // small delay for UI rendering update
  };

  const getSeverityBadge = (sev: string) => {
    const base = "px-2.5 py-0.5 rounded-full text-xs font-bold flex items-center w-fit";
    switch(sev.toUpperCase()) {
      case 'CRITICAL': return <span className={`${base} bg-red-100 text-red-700`}><ShieldAlert className="w-3 h-3 mr-1"/> CRITICAL</span>;
      case 'HIGH': return <span className={`${base} bg-orange-100 text-orange-700`}><AlertTriangle className="w-3 h-3 mr-1"/> HIGH</span>;
      case 'MEDIUM': return <span className={`${base} bg-yellow-100 text-yellow-700`}><AlertTriangle className="w-3 h-3 mr-1"/> MEDIUM</span>;
      case 'LOW': return <span className={`${base} bg-blue-100 text-blue-700`}><Info className="w-3 h-3 mr-1"/> LOW</span>;
      default: return <span className={`${base} bg-slate-100 text-slate-700`}>{sev}</span>;
    }
  };

  const getStorageIcon = (area: string) => {
    switch(area) {
      case 'shared_prefs': return <FileText className="w-5 h-5 text-purple-500" />;
      case 'databases': return <Database className="w-5 h-5 text-blue-500" />;
      case 'files': return <HardDrive className="w-5 h-5 text-green-500" />;
      case 'cache': return <HardDrive className="w-5 h-5 text-orange-500" />;
      default: return <Smartphone className="w-5 h-5 text-slate-500" />;
    }
  };

  // Consolidate findings for the table
  let allFindings: (Finding & { uid: string })[] = [];
  (report.storage_reports || []).forEach(sr => {
    (sr.findings || []).forEach((f, idx) => {
      allFindings.push({ ...f, uid: `dyn-${sr.area}-${idx}` });
    });
  });
  if (report.static_analysis && report.static_analysis.findings) {
    report.static_analysis.findings.forEach((f, idx) => {
      allFindings.push({ ...f, uid: `stat-${idx}` });
    });
  }
  
  // Sort by severity
  const sevOrder: Record<string, number> = { 'CRITICAL': 0, 'HIGH': 1, 'MEDIUM': 2, 'LOW': 3, 'INFO': 4 };
  allFindings.sort((a, b) => (sevOrder[a.severity] ?? 99) - (sevOrder[b.severity] ?? 99));

  return (
    <div className="max-w-6xl mx-auto space-y-6 pb-12">
      {/* Action Header (Not included in PDF) */}
      <div className="flex items-center justify-between mb-2">
        <Link to="/" className="flex items-center text-primary hover:underline text-sm font-medium">
          <ArrowLeft className="w-4 h-4 mr-1" /> Back to Dashboard
        </Link>
        <button 
          onClick={handleExportPDF}
          disabled={isExporting}
          className="flex items-center px-4 py-2 bg-slate-800 text-white text-sm font-medium rounded-lg shadow-sm hover:bg-slate-700 transition-colors disabled:opacity-50"
        >
          {isExporting ? (
            <span className="flex items-center"><div className="animate-spin rounded-full h-4 w-4 border-b-2 border-white mr-2"></div>Exporting...</span>
          ) : (
            <span className="flex items-center"><Download className="w-4 h-4 mr-2" />Export PDF</span>
          )}
        </button>
      </div>

      {/* Report Container (Target for PDF Export) */}
      <div ref={reportRef} className="space-y-6 bg-app pt-2">
        {/* Header */}
      <div className="flex items-center justify-between mb-8">
        <div>
          <h1 className="text-2xl font-bold text-slate-800">Security Report</h1>
          <p className="text-sm text-slate-500 mt-1">{report.static_analysis?.app_name || report.package_name || 'Unknown Package'} • Scan ID: {report.scan_id}</p>
        </div>
        <div className="text-right">
          <p className="text-xs text-slate-400">Analysed At</p>
          <p className="text-sm font-medium text-slate-700">{report.analysed_at ? new Date(report.analysed_at).toLocaleString() : 'N/A'}</p>
        </div>
      </div>

      {/* App Metadata Summary (Horizontal) */}
      <div className="bg-white rounded-2xl p-6 shadow-sm border border-slate-100 mb-6">
         <h3 className="text-sm font-bold text-slate-500 uppercase tracking-wider mb-4">App Metadata</h3>
         {report.static_analysis ? (
           <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
              <div className="bg-slate-50 p-3 rounded-lg border border-slate-100">
                <p className="text-xs text-slate-400 mb-1">APK Size</p>
                <p className="font-bold text-slate-700">
                  {report.static_analysis.apk_size_bytes 
                    ? `${(report.static_analysis.apk_size_bytes / (1024 * 1024)).toFixed(2)} MB` 
                    : 'N/A'}
                </p>
              </div>
              <div className="bg-slate-50 p-3 rounded-lg border border-slate-100">
                <p className="text-xs text-slate-400 mb-1">Native Architectures</p>
                <p className="text-sm font-medium text-slate-700 truncate" title={report.static_analysis.native_architectures?.join(', ')}>
                  {report.static_analysis.native_architectures?.length > 0 
                    ? report.static_analysis.native_architectures.join(', ') 
                    : 'None (Java/Kotlin)'}
                </p>
              </div>
              <div className="bg-slate-50 p-3 rounded-lg border border-slate-100">
                <p className="text-xs text-slate-400 mb-1">Entry Point</p>
                <p className="text-sm font-medium text-slate-700 truncate" title={report.static_analysis.launchable_activity}>
                  {report.static_analysis.launchable_activity?.split('.').pop() || 'N/A'}
                </p>
              </div>
              <div className="bg-slate-50 p-3 rounded-lg border border-slate-100">
                <p className="text-xs text-slate-400 mb-1">Hardware Features</p>
                <p className="text-sm text-slate-700 font-medium">
                  {report.static_analysis.uses_features?.length || 0} features requested
                </p>
              </div>
           </div>
         ) : (
           <p className="text-slate-500 text-sm">Metadata not available.</p>
         )}
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Risk Score Card */}
        <div className="bg-white rounded-2xl p-8 shadow-sm border border-slate-100 flex flex-col items-center justify-center text-center">
          <h3 className="text-sm font-bold text-slate-500 uppercase tracking-wider mb-4">Overall Risk Score</h3>
          <div className={`w-40 h-40 rounded-full border-8 flex flex-col items-center justify-center ${getRiskColor(report.risk_score || 0)}`}>
            <span className="text-5xl font-black">{report.risk_score || 0}</span>
            <span className="text-xs font-bold mt-1 opacity-80">/ 100</span>
          </div>
          <h2 className="mt-6 text-xl font-bold text-slate-800">{(report.risk_level || 'UNKNOWN').replace('_', ' ')}</h2>
          <p className="text-slate-500 text-sm mt-2">Based on {report.total_findings || 0} total findings across {report.total_files_scanned || 0} files.</p>
        </div>

        {/* Severity Breakdown Chart */}
        <div className="bg-white rounded-2xl p-6 shadow-sm border border-slate-100 flex flex-col">
          <h3 className="text-sm font-bold text-slate-500 uppercase tracking-wider mb-2">Severity Breakdown</h3>
          <div className="flex-1 flex items-center">
            <div className="w-1/2 h-full min-h-[160px] flex items-center justify-center">
              {isExporting ? (
                <PieChart width={200} height={160}>
                  <Pie data={severityData} innerRadius={40} outerRadius={70} paddingAngle={2} dataKey="value" stroke="none">
                    {severityData.map((entry, index) => (
                      <Cell key={`cell-${index}`} fill={entry.color} />
                    ))}
                  </Pie>
                  <Tooltip contentStyle={{ borderRadius: '8px', border: 'none', boxShadow: '0 4px 6px -1px rgb(0 0 0 / 0.1)' }} />
                </PieChart>
              ) : (
                <ResponsiveContainer width="100%" height="100%">
                  <PieChart>
                    <Pie data={severityData} innerRadius={40} outerRadius={70} paddingAngle={2} dataKey="value" stroke="none">
                      {severityData.map((entry, index) => (
                        <Cell key={`cell-${index}`} fill={entry.color} />
                      ))}
                    </Pie>
                    <Tooltip contentStyle={{ borderRadius: '8px', border: 'none', boxShadow: '0 4px 6px -1px rgb(0 0 0 / 0.1)' }} />
                  </PieChart>
                </ResponsiveContainer>
              )}
            </div>
            <div className="w-1/2 space-y-3 pl-4">
              {severityData.map(item => (
                <div key={item.name} className="flex justify-between items-center">
                  <div className="flex items-center text-sm">
                    <div className="w-3 h-3 rounded-full mr-2" style={{ backgroundColor: item.color }}></div>
                    <span className="text-slate-600 font-medium">{item.name}</span>
                  </div>
                  <span className="font-bold text-slate-800">{item.value}</span>
                </div>
              ))}
            </div>
          </div>
        </div>



        {/* Static Analysis Summary */}
        <div className="bg-white rounded-2xl p-6 shadow-sm border border-slate-100">
           <h3 className="text-sm font-bold text-slate-500 uppercase tracking-wider mb-4">App Manifest</h3>
           {report.static_analysis ? (
             <div className="space-y-4">
                <div className="grid grid-cols-2 gap-4">
                  <div className="bg-slate-50 p-3 rounded-lg border border-slate-100">
                    <p className="text-xs text-slate-400 mb-1">Target SDK</p>
                    <p className="font-bold text-slate-700">{report.static_analysis.target_sdk || 'N/A'}</p>
                  </div>
                  <div className="bg-slate-50 p-3 rounded-lg border border-slate-100">
                    <p className="text-xs text-slate-400 mb-1">Min SDK</p>
                    <p className="font-bold text-slate-700">{report.static_analysis.min_sdk || 'N/A'}</p>
                  </div>
                </div>
                <div>
                  <p className="text-xs text-slate-400 mb-2">Security Flags</p>
                  <div className="flex flex-wrap gap-2">
                    {report.static_analysis.manifest_flags?.debuggable && (
                      <span className="px-2 py-1 bg-red-100 text-red-700 text-xs font-bold rounded">DEBUGGABLE</span>
                    )}
                    {report.static_analysis.manifest_flags?.allow_backup && (
                      <span className="px-2 py-1 bg-orange-100 text-orange-700 text-xs font-bold rounded">allowBackup</span>
                    )}
                    {report.static_analysis.manifest_flags?.uses_cleartext_traffic && (
                      <span className="px-2 py-1 bg-orange-100 text-orange-700 text-xs font-bold rounded">Cleartext Traffic</span>
                    )}
                    {!report.static_analysis.manifest_flags?.debuggable && !report.static_analysis.manifest_flags?.allow_backup && !report.static_analysis.manifest_flags?.uses_cleartext_traffic && (
                      <span className="px-2 py-1 bg-green-100 text-green-700 text-xs font-bold rounded">No risky flags</span>
                    )}
                  </div>
                </div>
                <div className="pt-2 border-t border-slate-100">
                  <p className="text-xs text-slate-400 mb-1">Components</p>
                  <p className="text-sm text-slate-700 font-medium">
                    {report.static_analysis.total_permission_count || 0} Permissions 
                    ({report.static_analysis.dangerous_permission_count || 0} dangerous)
                  </p>
                </div>
             </div>
           ) : (
             <p className="text-slate-500 text-sm">Static analysis data not available.</p>
           )}
        </div>
      </div>

      {/* Storage Areas Summary */}
      <h3 className="text-lg font-bold text-slate-800 mt-10 mb-4">Storage Areas Analysed</h3>
      <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
        {report.storage_reports.map(area => (
          <div key={area.area} className="bg-white p-4 rounded-xl shadow-sm border border-slate-100 flex items-center">
            <div className="bg-slate-50 p-2 rounded-lg mr-3">
              {getStorageIcon(area.area)}
            </div>
            <div>
              <p className="font-bold text-slate-800 capitalize">{area.area.replace('_', ' ')}</p>
              <p className="text-xs text-slate-500">{area.findings.length} findings • {area.files_scanned} files</p>
            </div>
          </div>
        ))}
      </div>

      {/* Findings Table */}
      <h3 className="text-lg font-bold text-slate-800 mt-10 mb-4">Detailed Findings ({allFindings.length})</h3>
      <div className="bg-white rounded-2xl shadow-sm border border-slate-200 overflow-hidden">
        <div className="overflow-x-auto">
          <table className="w-full text-left text-sm">
            <thead className="bg-slate-50 border-b border-slate-200 text-slate-500">
              <tr>
                <th className="px-6 py-4 font-semibold w-10"></th>
                <th className="px-6 py-4 font-semibold">Severity</th>
                <th className="px-6 py-4 font-semibold">Rule / Category</th>
                <th className="px-6 py-4 font-semibold">Location</th>
                <th className="px-6 py-4 font-semibold">Key / Field</th>
                <th className="px-6 py-4 font-semibold">Value Preview</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-100">
              {allFindings.length === 0 ? (
                <tr>
                  <td colSpan={6} className="px-6 py-8 text-center text-slate-500">No findings to display.</td>
                </tr>
              ) : (
                allFindings.map((finding) => {
                  const isExpanded = expandedFindings.has(finding.uid);
                  return (
                    <React.Fragment key={finding.uid}>
                      <tr 
                        className={`hover:bg-slate-50 cursor-pointer transition-colors ${isExpanded ? 'bg-slate-50' : ''}`}
                        onClick={() => toggleFinding(finding.uid)}
                      >
                        <td className="px-6 py-4">
                          {isExpanded ? <ChevronUp className="w-4 h-4 text-slate-400" /> : <ChevronDown className="w-4 h-4 text-slate-400" />}
                        </td>
                        <td className="px-6 py-4">
                          {getSeverityBadge(finding.severity)}
                        </td>
                        <td className="px-6 py-4">
                          <div className="font-bold text-slate-800">{finding.rule_name}</div>
                          <div className="text-xs text-slate-500 uppercase">{finding.category}</div>
                        </td>
                        <td className="px-6 py-4">
                          <div className="flex items-center">
                            {getStorageIcon(finding.storage_area)}
                            <span className="ml-2 font-medium text-slate-700 max-w-[150px] truncate" title={finding.file_path}>
                              {finding.file_path.split('/').pop() || finding.file_path}
                            </span>
                          </div>
                        </td>
                        <td className="px-6 py-4 font-mono text-xs text-slate-700">
                          {finding.key_or_field || '-'}
                        </td>
                        <td className="px-6 py-4">
                          <code className="bg-slate-100 text-slate-700 px-2 py-1 rounded text-xs font-mono">
                            {finding.value_preview || '-'}
                          </code>
                        </td>
                      </tr>
                      {isExpanded && (
                        <tr className="bg-slate-50 border-b-2 border-slate-200">
                          <td colSpan={6} className="px-6 py-6 pl-16">
                            <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                              <div>
                                <h4 className="text-xs font-bold text-slate-400 uppercase tracking-wider mb-2">Description</h4>
                                <p className="text-sm text-slate-700 leading-relaxed bg-white p-4 rounded-lg border border-slate-200 shadow-sm">
                                  {finding.description}
                                </p>
                              </div>
                              <div>
                                <h4 className="text-xs font-bold text-slate-400 uppercase tracking-wider mb-2">Recommendation</h4>
                                <p className="text-sm text-slate-700 leading-relaxed bg-primary/5 border border-primary/20 p-4 rounded-lg">
                                  {finding.recommendation}
                                </p>
                              </div>
                            </div>
                            <div className="mt-4">
                               <h4 className="text-xs font-bold text-slate-400 uppercase tracking-wider mb-2">Full Path</h4>
                               <code className="text-xs text-slate-600 bg-slate-200 px-2 py-1 rounded break-all">
                                 {finding.file_path}
                               </code>
                            </div>
                          </td>
                        </tr>
                      )}
                    </React.Fragment>
                  );
                })
              )}
            </tbody>
          </table>
        </div>
        </div>
      </div>
    </div>
  );
}
