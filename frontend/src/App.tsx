import { useState, useRef, useEffect } from 'react';
import { BrowserRouter, Routes, Route, Link, useLocation, Navigate } from 'react-router-dom';
import { LayoutDashboard, History, Shield, Settings, Bell, Search, User as UserIcon, LogOut } from 'lucide-react';
import { AuthProvider, useAuth } from './context/AuthContext';
import LoginPage from './pages/LoginPage';
import RegisterPage from './pages/RegisterPage';
import HomePage from './pages/HomePage';
import ScanProgressPage from './pages/ScanProgressPage';
import ReportPage from './pages/ReportPage';
import HistoryPage from './pages/HistoryPage';

// Protected Route Component
const ProtectedRoute = ({ children }: { children: React.ReactNode }) => {
  const { user, isLoading } = useAuth();
  
  if (isLoading) {
    return <div className="flex h-screen items-center justify-center bg-slate-50"><div className="animate-spin rounded-full h-12 w-12 border-b-2 border-primary"></div></div>;
  }
  
  if (!user) {
    return <Navigate to="/login" replace />;
  }
  
  return <>{children}</>;
};

// Layout wrapper component
const Layout = ({ children }: { children: React.ReactNode }) => {
  const location = useLocation();
  const path = location.pathname;

  const [activeDropdown, setActiveDropdown] = useState<'none' | 'notifications' | 'settings' | 'profile'>('none');
  const dropdownRef = useRef<HTMLDivElement>(null);
  const { user, logout } = useAuth();

  useEffect(() => {
    const handleClickOutside = (event: MouseEvent) => {
      if (dropdownRef.current && !dropdownRef.current.contains(event.target as Node)) {
        setActiveDropdown('none');
      }
    };
    document.addEventListener('mousedown', handleClickOutside);
    return () => document.removeEventListener('mousedown', handleClickOutside);
  }, []);

  return (
    <div className="flex h-screen bg-app overflow-hidden">
      {/* Sidebar */}
      <aside className="w-64 bg-sidebar text-slate-300 flex flex-col shrink-0">
        <div className="h-16 flex items-center px-6 font-bold text-xl text-white tracking-wide border-b border-slate-700/50">
          <Shield className="w-6 h-6 mr-3 text-cyan" />
          VaultDex
        </div>
        
        <nav className="flex-1 py-6 px-4 space-y-1">
          <div className="px-3 text-xs font-semibold text-slate-500 uppercase tracking-wider mb-2">Main Menu</div>
          
          <Link 
            to="/" 
            className={`flex items-center px-3 py-2.5 text-sm font-medium rounded-lg transition-colors ${path === '/' ? 'bg-primary/10 text-primary' : 'hover:bg-slate-800 hover:text-white'}`}
          >
            <LayoutDashboard className="w-5 h-5 mr-3 opacity-75" />
            Dashboard
          </Link>

          <Link 
            to="/history" 
            className={`flex items-center px-3 py-2.5 text-sm font-medium rounded-lg transition-colors ${path === '/history' ? 'bg-primary/10 text-primary' : 'hover:bg-slate-800 hover:text-white'}`}
          >
            <History className="w-5 h-5 mr-3 opacity-75" />
            Scan History
          </Link>
        </nav>
      </aside>

      {/* Main Content Area */}
      <div className="flex-1 flex flex-col min-w-0">
        {/* Top Header */}
        <header className="h-16 bg-white border-b border-slate-200 flex items-center justify-between px-6 shrink-0">
          <div className="flex items-center w-96">
            <div className="relative w-full">
              <div className="absolute inset-y-0 left-0 pl-3 flex items-center pointer-events-none">
                <Search className="h-4 w-4 text-slate-400" />
              </div>
              <input
                type="text"
                className="block w-full pl-10 pr-3 py-2 border border-slate-200 rounded-lg text-sm placeholder-slate-400 focus:outline-none focus:border-primary focus:ring-1 focus:ring-primary bg-slate-50 transition-colors"
                placeholder="Search scans, packages..."
              />
            </div>
          </div>
          <div className="flex items-center space-x-4" ref={dropdownRef}>
            {/* Notifications */}
            <div className="relative">
              <button 
                className="p-2 text-slate-400 hover:text-slate-600 rounded-full hover:bg-slate-100 transition-colors focus:outline-none"
                onClick={() => setActiveDropdown(activeDropdown === 'notifications' ? 'none' : 'notifications')}
              >
                <Bell className="h-5 w-5" />
              </button>
              {activeDropdown === 'notifications' && (
                <div className="absolute right-0 mt-2 w-64 bg-white rounded-xl shadow-lg border border-slate-100 py-2 z-50">
                  <div className="px-4 py-2 border-b border-slate-100">
                    <h4 className="text-sm font-bold text-slate-700">Notifications</h4>
                  </div>
                  <div className="p-4 text-center text-sm text-slate-500">
                    No new notifications
                  </div>
                </div>
              )}
            </div>

            {/* Settings */}
            <div className="relative">
              <button 
                className="p-2 text-slate-400 hover:text-slate-600 rounded-full hover:bg-slate-100 transition-colors focus:outline-none"
                onClick={() => setActiveDropdown(activeDropdown === 'settings' ? 'none' : 'settings')}
              >
                <Settings className="h-5 w-5" />
              </button>
              {activeDropdown === 'settings' && (
                <div className="absolute right-0 mt-2 w-48 bg-white rounded-xl shadow-lg border border-slate-100 py-2 z-50">
                  <div className="px-4 py-2">
                    <p className="text-sm text-slate-500 italic">Settings coming soon</p>
                  </div>
                </div>
              )}
            </div>

            {/* Profile */}
            <div className="relative ml-2">
              <button 
                className="h-8 w-8 rounded-full bg-primary/20 text-primary flex items-center justify-center font-bold text-sm focus:outline-none focus:ring-2 focus:ring-primary focus:ring-offset-2 uppercase"
                onClick={() => setActiveDropdown(activeDropdown === 'profile' ? 'none' : 'profile')}
              >
                {user?.email?.[0] || 'U'}
              </button>
              {activeDropdown === 'profile' && (
                <div className="absolute right-0 mt-2 w-48 bg-white rounded-xl shadow-lg border border-slate-100 py-1 z-50">
                  <div className="px-4 py-3 border-b border-slate-100">
                    <p className="text-sm font-medium text-slate-900 truncate">{user?.full_name || 'User'}</p>
                    <p className="text-xs text-slate-500 truncate">{user?.email}</p>
                  </div>
                  <button className="w-full text-left px-4 py-2 text-sm text-slate-700 hover:bg-slate-50 flex items-center">
                    <UserIcon className="w-4 h-4 mr-2" />
                    Your Profile
                  </button>
                  <button 
                    onClick={logout}
                    className="w-full text-left px-4 py-2 text-sm text-red-600 hover:bg-red-50 flex items-center"
                  >
                    <LogOut className="w-4 h-4 mr-2" />
                    Sign out
                  </button>
                </div>
              )}
            </div>
          </div>
        </header>

        {/* Scrollable Content */}
        <main className="flex-1 overflow-y-auto bg-slate-50 p-8">
          {children}
        </main>
      </div>
    </div>
  );
};

export default function App() {
  return (
    <BrowserRouter>
      <AuthProvider>
        <Routes>
          {/* Public Routes */}
          <Route path="/login" element={<LoginPage />} />
          <Route path="/register" element={<RegisterPage />} />
          
          {/* Protected Routes */}
          <Route path="/" element={<ProtectedRoute><Layout><HomePage /></Layout></ProtectedRoute>} />
          <Route path="/scans/active/:scanId" element={<ProtectedRoute><Layout><ScanProgressPage /></Layout></ProtectedRoute>} />
          <Route path="/scans/report/:scanId" element={<ProtectedRoute><Layout><ReportPage /></Layout></ProtectedRoute>} />
          <Route path="/history" element={<ProtectedRoute><Layout><HistoryPage /></Layout></ProtectedRoute>} />
        </Routes>
      </AuthProvider>
    </BrowserRouter>
  );
}
