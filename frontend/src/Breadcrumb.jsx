import React from 'react';
import { Link, useLocation } from 'react-router-dom';

const LABELS = {
  dashboard: 'Dashboard',
  report: 'Report',
  admin: 'Admin',
  dev: 'Developer',
  lab: 'Lab',
  'review-gate': 'Review Gate',
};

const Breadcrumb = () => {
  const { pathname } = useLocation();
  const segments = pathname.split('/').filter(Boolean);

  const crumbs = [{ label: 'SmartFuzzQL', to: '/', isLast: false }];
  segments.forEach((seg, i) => {
    const to = '/' + segments.slice(0, i + 1).join('/');
    const label = LABELS[seg] ?? (seg.length > 8 ? `${seg.slice(0, 8)}...` : seg);
    crumbs.push({ label, to, isLast: i === segments.length - 1 });
  });

  return (
    <nav className="flex items-center space-x-1 text-sm text-gray-400">
      {crumbs.map((crumb, i) => (
        <React.Fragment key={crumb.to}>
          {i > 0 && <span className="text-gray-600 select-none">/</span>}
          {crumb.isLast ? (
            <span className="text-white">{crumb.label}</span>
          ) : (
            <Link to={crumb.to} className="hover:text-blue-400 transition-colors">
              {crumb.label}
            </Link>
          )}
        </React.Fragment>
      ))}
    </nav>
  );
};

export default Breadcrumb;
