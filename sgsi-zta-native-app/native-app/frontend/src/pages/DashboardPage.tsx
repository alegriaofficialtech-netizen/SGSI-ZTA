import { lazy, Suspense } from 'react';
import { Loading } from '../components/Status';

const Dashboard = lazy(() =>
  import('./Dashboard').then((module) => ({ default: module.Dashboard })),
);

export function DashboardPage() {
  return (
    <Suspense fallback={<Loading />}>
      <Dashboard />
    </Suspense>
  );
}
