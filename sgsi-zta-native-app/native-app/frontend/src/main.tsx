import { createRoot } from 'react-dom/client';
import { BrowserRouter, Navigate, Route, Routes } from 'react-router-dom';
import { AuthProvider } from './auth/AuthProvider';
import { Protected } from './auth/Protected';
import { AppLayout } from './layouts/AppLayout';
import { Login } from './pages/Login';
import { Mfa } from './pages/Mfa';
import { DashboardPage } from './pages/DashboardPage';
import { Users } from './pages/Users';
import { Assets } from './pages/Assets';
import { AssetDetail } from './pages/AssetDetail';
import { AssetForm } from './pages/AssetForm';
import { GovernanceList } from './pages/GovernanceList';
import { GovernanceForm } from './pages/GovernanceForm';
import { RiskDetail, ControlDetail } from './pages/GovernanceDetail';
import { RiskMatrix } from './pages/RiskMatrix';
import { Audit } from './pages/Audit';
import { Settings } from './pages/Settings';
import { PendingModule } from './pages/PendingModule';

// M5 Zero Trust & Clinical Demo Pages
import { ZeroTrustDashboard } from './pages/ZeroTrustDashboard';
import { PolicyList } from './pages/PolicyList';
import { PolicyForm } from './pages/PolicyForm';
import { PolicyDetail } from './pages/PolicyDetail';
import { ZeroTrustSimulator } from './pages/ZeroTrustSimulator';
import { DecisionList } from './pages/DecisionList';
import { DecisionDetail } from './pages/DecisionDetail';
import { ClinicalDemo } from './pages/ClinicalDemo';

// M6 Monitoring & Alerts Pages
import { MonitoringDashboard } from './pages/monitoring/MonitoringDashboard';
import { EventsList } from './pages/monitoring/EventsList';
import { EventDetail } from './pages/monitoring/EventDetail';
import { AlertsList } from './pages/monitoring/AlertsList';
import { AlertDetail } from './pages/monitoring/AlertDetail';
import { RulesList } from './pages/monitoring/RulesList';
import { RuleForm } from './pages/monitoring/RuleForm';
import { SourcesList } from './pages/monitoring/SourcesList';
import { FimList } from './pages/monitoring/FimList';
import { FimDetail } from './pages/monitoring/FimDetail';

import './styles.css';

createRoot(document.getElementById('root')!).render(
  <BrowserRouter>
    <AuthProvider>
      <Routes>
        <Route path="/login" element={<Login />} />
        <Route path="/mfa" element={<Mfa />} />
        <Route path="/mfa/setup" element={<Mfa />} />
        <Route element={<Protected />}>
          <Route element={<AppLayout />}>
            <Route path="/dashboard" element={<DashboardPage />} />
            <Route path="/users" element={<Users />} />
            <Route path="/assets" element={<Assets />} />
            <Route path="/assets/new" element={<AssetForm />} />
            <Route path="/assets/:id" element={<AssetDetail />} />
            <Route path="/assets/:id/edit" element={<AssetForm />} />
            <Route path="/risks" element={<GovernanceList kind="risks" />} />
            <Route path="/risks/new" element={<GovernanceForm kind="risks" />} />
            <Route path="/risks/matrix" element={<RiskMatrix />} />
            <Route path="/risks/:id" element={<RiskDetail />} />
            <Route path="/risks/:id/edit" element={<GovernanceForm kind="risks" />} />
            <Route path="/controls" element={<GovernanceList kind="controls" />} />
            <Route path="/controls/new" element={<GovernanceForm kind="controls" />} />
            <Route path="/controls/:id" element={<ControlDetail />} />
            <Route path="/controls/:id/edit" element={<GovernanceForm kind="controls" />} />
            <Route path="/audit" element={<Audit />} />
            <Route path="/settings" element={<Settings />} />

            {/* M5 Zero Trust Routes */}
            <Route path="/zero-trust" element={<ZeroTrustDashboard />} />
            <Route path="/zero-trust/policies" element={<PolicyList />} />
            <Route path="/zero-trust/policies/new" element={<PolicyForm />} />
            <Route path="/zero-trust/policies/:id" element={<PolicyDetail />} />
            <Route path="/zero-trust/policies/:id/edit" element={<PolicyForm />} />
            <Route path="/zero-trust/simulator" element={<ZeroTrustSimulator />} />
            <Route path="/zero-trust/decisions" element={<DecisionList />} />
            <Route path="/zero-trust/decisions/:id" element={<DecisionDetail />} />

            {/* M6 Monitoring Routes */}
            <Route path="/monitoring" element={<MonitoringDashboard />} />
            <Route path="/monitoring/events" element={<EventsList />} />
            <Route path="/monitoring/events/:id" element={<EventDetail />} />
            <Route path="/monitoring/alerts" element={<AlertsList />} />
            <Route path="/monitoring/alerts/:id" element={<AlertDetail />} />
            <Route path="/monitoring/rules" element={<RulesList />} />
            <Route path="/monitoring/rules/new" element={<RuleForm />} />
            <Route path="/monitoring/rules/:id" element={<RuleForm />} />
            <Route path="/monitoring/sources" element={<SourcesList />} />
            <Route path="/monitoring/fim" element={<FimList />} />
            <Route path="/monitoring/fim/:id" element={<FimDetail />} />

            {/* Clinical Demo Route */}
            <Route path="/clinical" element={<ClinicalDemo />} />

            <Route path="/" element={<Navigate to="/dashboard" replace />} />
            <Route path="*" element={<PendingModule />} />
          </Route>
        </Route>
      </Routes>
    </AuthProvider>
  </BrowserRouter>,
);
