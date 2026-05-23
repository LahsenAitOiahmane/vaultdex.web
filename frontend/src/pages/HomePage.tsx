import { useState, useEffect } from 'react';
import { UploadCloud, ShieldAlert, Activity, CheckCircle, Clock } from 'lucide-react';
import { useNavigate } from 'react-router-dom';
import { api } from '../api/client';
import type { DashboardStats } from '../api/client';
import { AreaChart, Area, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer, PieChart, Pie, Cell } from 'recharts';

const COLORS = {
  PASS: '#2ed8b6',
  LOW_RISK: '#3b82f6',
  MEDIUM_RISK: '#eab308',
  HIGH_RISK: '#f97316',
  CRITICAL_RISK: '#ef4444',
  UNKNOWN: '#94a3b8'
};

export default function HomePage() {
  const navigate = useNavigate();
  const [isUploading, setIsUploading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [stats, setStats] = useState<DashboardStats | null>(null);

  useEffect(() => {
    const fetchStats = async () => {
      try {
        const response = await api.get('/scans/stats');
        setStats(response.data);
      } catch (err) {
        console.error('Failed to fetch stats:', err);
      }
    };
    fetchStats();
  }, []);

  const handleFileUpload = async (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;

    setIsUploading(true);
    setError(null);

    const formData = new FormData();
    formData.append('file', file);

    try {
      const response = await api.post('/scans', formData, {
        headers: { 'Content-Type': 'multipart/form-data' },
      });
      // Navigate to the live progress page for this scan
      navigate(`/scans/active/${response.data.scan_id}`);
    } catch (err: any) {
      console.error('Upload failed:', err);
      setError(err.response?.data?.detail || 'Failed to upload APK.');
      setIsUploading(false);
    }
  };

  return (
    <div className="space-y-6">
      <div className="flex justify-between items-center mb-8">
        <div>
          <h1 className="text-2xl font-bold text-slate-800">Dashboard</h1>
          <p className="text-sm text-slate-500 mt-1">Home &gt; Dashboard &gt; Overview</p>
        </div>
      </div>

      {/* Upload Area */}
      <div className="bg-white rounded-2xl p-8 shadow-sm border border-slate-100 flex flex-col items-center justify-center border-dashed border-2 border-primary/30 hover:border-primary transition-colors relative overflow-hidden group">
        <input 
          type="file" 
          accept=".apk"
          onChange={handleFileUpload}
          disabled={isUploading}
          className="absolute inset-0 w-full h-full opacity-0 cursor-pointer z-10"
        />
        <div className="bg-primary/10 p-4 rounded-full mb-4 group-hover:scale-110 transition-transform">
          <UploadCloud className="w-8 h-8 text-primary" />
        </div>
        <h2 className="text-xl font-bold text-slate-800">
          {isUploading ? 'Uploading...' : 'Upload new APK'}
        </h2>
        <p className="text-slate-500 text-sm mt-2">
          Drag and drop your Android package (.apk) here, or click to browse.
        </p>
        
        {error && (
          <div className="mt-4 text-red-500 text-sm font-medium bg-red-50 px-4 py-2 rounded-lg">
            {error}
          </div>
        )}
      </div>

      {/* Stat Cards Row */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
        {/* Card 1: Blue */}
        <div className="bg-primary rounded-2xl p-6 shadow-md text-white relative overflow-hidden">
          <div className="absolute -right-6 -top-6 w-24 h-24 bg-white/10 rounded-full blur-xl"></div>
          <p className="text-white/80 text-sm font-medium mb-1">Total Scans</p>
          <h3 className="text-3xl font-bold">{stats?.total_scans || 0}</h3>
          <p className="text-white/80 text-xs mt-2 flex items-center">
            Across all uploaded APKs
          </p>
          <Activity className="absolute bottom-6 right-6 w-12 h-12 text-white/20" />
        </div>

        {/* Card 2: Cyan */}
        <div className="bg-[#00bcd4] rounded-2xl p-6 shadow-md text-white relative overflow-hidden">
          <div className="absolute -right-6 -top-6 w-24 h-24 bg-white/10 rounded-full blur-xl"></div>
          <p className="text-white/80 text-sm font-medium mb-1">Vulnerabilities Found</p>
          <h3 className="text-3xl font-bold">{stats?.vulnerabilities_found || 0}</h3>
          <p className="text-white/80 text-xs mt-2 flex items-center">
            Total risks identified
          </p>
          <ShieldAlert className="absolute bottom-6 right-6 w-12 h-12 text-white/20" />
        </div>

        {/* Card 3: Green */}
        <div className="bg-[#2ed8b6] rounded-2xl p-6 shadow-md text-white relative overflow-hidden">
          <div className="absolute -right-6 -top-6 w-24 h-24 bg-white/10 rounded-full blur-xl"></div>
          <p className="text-white/80 text-sm font-medium mb-1">Safe Apps</p>
          <h3 className="text-3xl font-bold">
            {stats?.total_scans ? Math.round((stats.safe_apps / stats.total_scans) * 100) : 0}%
          </h3>
          <p className="text-white/80 text-xs mt-2 flex items-center">
            Risk score below 40
          </p>
          <CheckCircle className="absolute bottom-6 right-6 w-12 h-12 text-white/20" />
        </div>

        {/* Card 4: Purple */}
        <div className="bg-[#7e57c2] rounded-2xl p-6 shadow-md text-white relative overflow-hidden">
          <div className="absolute -right-6 -top-6 w-24 h-24 bg-white/10 rounded-full blur-xl"></div>
          <p className="text-white/80 text-sm font-medium mb-1">Avg. Scan Time</p>
          <h3 className="text-3xl font-bold">{Math.round(stats?.avg_scan_time || 0)}s</h3>
          <p className="text-white/80 text-xs mt-2 flex items-center">
            Processing duration
          </p>
          <Clock className="absolute bottom-6 right-6 w-12 h-12 text-white/20" />
        </div>
      </div>

      {/* Charts Row */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Main Chart */}
        <div className="bg-white rounded-2xl p-6 shadow-sm border border-slate-100 lg:col-span-2">
          <div className="flex justify-between items-center mb-6">
            <h3 className="text-lg font-bold text-slate-800">Scans Analytics (7 Days)</h3>
          </div>
          <div className="h-72">
            <ResponsiveContainer width="100%" height="100%">
              <AreaChart data={stats?.daily_stats || []} margin={{ top: 10, right: 10, left: -20, bottom: 0 }}>
                <defs>
                  <linearGradient id="colorUv" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="5%" stopColor="#4099ff" stopOpacity={0.3}/>
                    <stop offset="95%" stopColor="#4099ff" stopOpacity={0}/>
                  </linearGradient>
                </defs>
                <CartesianGrid strokeDasharray="3 3" vertical={false} stroke="#e2e8f0" />
                <XAxis dataKey="name" axisLine={false} tickLine={false} tick={{fill: '#94a3b8', fontSize: 12}} dy={10} />
                <YAxis axisLine={false} tickLine={false} tick={{fill: '#94a3b8', fontSize: 12}} allowDecimals={false} />
                <Tooltip 
                  contentStyle={{ borderRadius: '8px', border: 'none', boxShadow: '0 4px 6px -1px rgb(0 0 0 / 0.1)' }}
                />
                <Area type="monotone" dataKey="value" name="Scans" stroke="#4099ff" strokeWidth={3} fillOpacity={1} fill="url(#colorUv)" />
              </AreaChart>
            </ResponsiveContainer>
          </div>
        </div>

        {/* Risk Distribution */}
        <div className="bg-white rounded-2xl p-6 shadow-sm border border-slate-100">
          <h3 className="text-lg font-bold text-slate-800 mb-6">Risk Distribution</h3>
          <div className="h-48 relative flex items-center justify-center">
            {stats && Object.keys(stats.risk_distribution).length > 0 ? (
              <ResponsiveContainer width="100%" height="100%">
                <PieChart>
                  <Pie
                    data={Object.entries(stats.risk_distribution).map(([key, value]) => ({ name: key.replace('_', ' '), value, rawKey: key }))}
                    innerRadius={60}
                    outerRadius={80}
                    paddingAngle={5}
                    dataKey="value"
                    stroke="none"
                  >
                    {Object.entries(stats.risk_distribution).map(([key], index) => (
                      <Cell key={`cell-${index}`} fill={(COLORS as any)[key] || COLORS.UNKNOWN} />
                    ))}
                  </Pie>
                </PieChart>
              </ResponsiveContainer>
            ) : (
              <div className="text-slate-400 flex flex-col items-center">
                <ShieldAlert className="w-8 h-8 mb-2 opacity-50" />
                <span>No data yet</span>
              </div>
            )}
            {stats && Object.keys(stats.risk_distribution).length > 0 && (
               <ShieldAlert className="absolute w-8 h-8 text-slate-400" />
            )}
          </div>
          
          <div className="mt-6 space-y-4">
            {stats && Object.entries(stats.risk_distribution).map(([key, val]) => {
              const total = Object.values(stats.risk_distribution).reduce((a, b) => a + b, 0);
              const percentage = total > 0 ? Math.round((val / total) * 100) : 0;
              return (
                <div key={key}>
                  <div className="flex justify-between text-sm mb-1">
                    <span className="text-slate-600 font-medium capitalize">{key.replace('_', ' ').toLowerCase()}</span>
                    <span className="text-slate-800 font-bold">{percentage}%</span>
                  </div>
                  <div className="w-full bg-slate-100 rounded-full h-2">
                    <div 
                      className="h-2 rounded-full" 
                      style={{ width: `${percentage}%`, backgroundColor: (COLORS as any)[key] || COLORS.UNKNOWN }}
                    ></div>
                  </div>
                </div>
              );
            })}
          </div>
        </div>
      </div>
    </div>
  );
}
