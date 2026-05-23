import { useEffect, useState } from 'react';
import { Link } from 'react-router-dom';
import { Search, ChevronRight, ShieldAlert, ShieldCheck } from 'lucide-react';
import { api } from '../api/client';
import type { ScanListItem } from '../api/client';

export default function HistoryPage() {
  const [scans, setScans] = useState<ScanListItem[]>([]);
  const [isLoading, setIsLoading] = useState(true);
  const [searchTerm, setSearchTerm] = useState('');

  useEffect(() => {
    const fetchScans = async () => {
      try {
        const response = await api.get('/scans');
        setScans(response.data.scans || []);
      } catch (err) {
        console.error("Failed to fetch scan history", err);
      } finally {
        setIsLoading(false);
      }
    };
    fetchScans();
  }, []);

  const filteredScans = scans.filter(scan => {
    if (!searchTerm) return true;
    const term = searchTerm.toLowerCase();
    return (
      scan.package_name?.toLowerCase().includes(term) ||
      scan.scan_id.toLowerCase().includes(term)
    );
  });

  const getStatusBadge = (status: string) => {
    switch(status) {
      case 'COMPLETED': return <span className="px-2 py-1 bg-green-100 text-green-700 text-xs font-bold rounded-full">Completed</span>;
      case 'FAILED': return <span className="px-2 py-1 bg-red-100 text-red-700 text-xs font-bold rounded-full">Failed</span>;
      case 'WAITING_FOR_USER': return <span className="px-2 py-1 bg-blue-100 text-blue-700 text-xs font-bold rounded-full">Action Required</span>;
      default: return <span className="px-2 py-1 bg-slate-100 text-slate-700 text-xs font-bold rounded-full">{status}</span>;
    }
  };

  const getScoreBadge = (score: number | null) => {
    if (score === null) return <span className="text-slate-400">-</span>;
    
    let color = 'text-green-500 bg-green-50 border-green-200';
    let Icon = ShieldCheck;
    
    if (score >= 80) { color = 'text-red-500 bg-red-50 border-red-200'; Icon = ShieldAlert; }
    else if (score >= 60) { color = 'text-orange-500 bg-orange-50 border-orange-200'; Icon = ShieldAlert; }
    else if (score >= 40) { color = 'text-yellow-500 bg-yellow-50 border-yellow-200'; Icon = ShieldAlert; }

    return (
      <span className={`px-2.5 py-1 rounded-full text-xs font-bold flex items-center w-fit border ${color}`}>
        <Icon className="w-3 h-3 mr-1" />
        {score}
      </span>
    );
  };

  return (
    <div className="max-w-6xl mx-auto space-y-6">
      <div className="flex justify-between items-center mb-8">
        <div>
          <h1 className="text-2xl font-bold text-slate-800">Scan History</h1>
          <p className="text-sm text-slate-500 mt-1">Home &gt; Scan History</p>
        </div>
        <div className="relative">
          <div className="absolute inset-y-0 left-0 pl-3 flex items-center pointer-events-none">
            <Search className="h-4 w-4 text-slate-400" />
          </div>
          <input
            type="text"
            value={searchTerm}
            onChange={(e) => setSearchTerm(e.target.value)}
            className="block w-64 pl-10 pr-3 py-2 border border-slate-200 rounded-lg text-sm focus:outline-none focus:border-primary focus:ring-1 focus:ring-primary bg-white shadow-sm"
            placeholder="Search by package name or ID..."
          />
        </div>
      </div>

      <div className="bg-white rounded-2xl shadow-sm border border-slate-200 overflow-hidden">
        {isLoading ? (
          <div className="p-8 text-center text-slate-500 animate-pulse">Loading scan history...</div>
        ) : filteredScans.length === 0 ? (
          <div className="p-8 text-center text-slate-500">No scans found.</div>
        ) : (
          <table className="w-full text-left text-sm">
            <thead className="bg-slate-50 border-b border-slate-200 text-slate-500 uppercase text-xs tracking-wider">
              <tr>
                <th className="px-6 py-4 font-semibold">Package / ID</th>
                <th className="px-6 py-4 font-semibold">Date</th>
                <th className="px-6 py-4 font-semibold">Status</th>
                <th className="px-6 py-4 font-semibold">Risk Score</th>
                <th className="px-6 py-4 font-semibold text-right">Action</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-100">
              {filteredScans.map((scan) => (
                <tr key={scan.scan_id} className="hover:bg-slate-50 transition-colors">
                  <td className="px-6 py-4">
                    <div className="font-bold text-slate-800">{scan.package_name || 'Unknown Package'}</div>
                    <div className="text-xs text-slate-400 font-mono mt-1">{scan.scan_id}</div>
                  </td>
                  <td className="px-6 py-4 text-slate-600">
                    {new Date(scan.created_at).toLocaleDateString()}
                    <div className="text-xs text-slate-400 mt-1">
                      {new Date(scan.created_at).toLocaleTimeString()}
                    </div>
                  </td>
                  <td className="px-6 py-4">
                    {getStatusBadge(scan.status)}
                  </td>
                  <td className="px-6 py-4">
                    {getScoreBadge(scan.risk_score)}
                  </td>
                  <td className="px-6 py-4 text-right">
                    {scan.status === 'COMPLETED' ? (
                      <Link 
                        to={`/scans/report/${scan.scan_id}`}
                        className="inline-flex items-center text-primary hover:text-blue-700 font-medium"
                      >
                        View Report <ChevronRight className="w-4 h-4 ml-1" />
                      </Link>
                    ) : scan.status === 'WAITING_FOR_USER' || scan.status === 'QUEUED' || scan.status === 'FINALIZING' ? (
                      <Link 
                        to={`/scans/active/${scan.scan_id}`}
                        className="inline-flex items-center text-blue-500 hover:text-blue-700 font-medium"
                      >
                        Resume <ChevronRight className="w-4 h-4 ml-1" />
                      </Link>
                    ) : (
                      <span className="text-slate-400">-</span>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>
    </div>
  );
}
