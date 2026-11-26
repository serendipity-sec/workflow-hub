import { BrowserRouter, Route, Routes } from 'react-router';
import { AuthProvider } from '../features/auth/AuthProvider';
import { RequireAuth } from '../features/auth/RequireAuth';
import { HomePage } from '../features/home/HomePage';
import { WorkflowDetailPage } from '../features/workflows/WorkflowDetailPage';
import { WorkflowListPage } from '../features/workflows/WorkflowListPage';
import { WorkflowUploadPage } from '../features/workflows/WorkflowUploadPage';
import { Layout } from './Layout';
import { NotFoundPage } from './NotFoundPage';

export function App() {
  return (
    <BrowserRouter>
      <AuthProvider>
        <Routes>
          <Route element={<Layout />}>
            <Route index element={<HomePage />} />
            <Route element={<RequireAuth />}>
              <Route path="workflows" element={<WorkflowListPage />} />
              <Route path="workflows/new" element={<WorkflowUploadPage />} />
              <Route
                path="workflows/:workflowId"
                element={<WorkflowDetailPage />}
              />
            </Route>
            <Route path="*" element={<NotFoundPage />} />
          </Route>
        </Routes>
      </AuthProvider>
    </BrowserRouter>
  );
}
