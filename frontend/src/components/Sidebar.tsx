import { NavLink } from 'react-router-dom';

const navigation = [
  { label: 'Dashboard', to: '/', code: 'OV' },
  { label: 'Alerts', to: '/alerts', code: 'AL' },
  { label: 'Incidents', to: '/incidents', code: 'IR' },
  { label: 'Assets', to: '/assets', code: 'AS' },
  { label: 'Network', to: '/network', code: 'NW' },
  { label: 'AI Detection', to: '/ai-detection', code: 'AI' },
  { label: 'Logs', to: '/logs', code: 'LG' },
  { label: 'Reports', to: '/reports', code: 'RP' },
  { label: 'Simulations', to: '/simulations', code: 'LB' },
];

const Sidebar = () => {
  return (
    <aside className="soc-sidebar">
      <div className="soc-sidebar__brand">
        <span className="soc-sidebar__mark" aria-hidden="true">S</span>
        <div>
          <p className="soc-sidebar__brand-name">Industrial SOC</p>
          <p className="soc-sidebar__brand-caption">Security operations</p>
        </div>
      </div>
      <p className="soc-sidebar__section-label">Workspace</p>
      <nav aria-label="Main navigation" className="soc-sidebar__nav">
        {navigation.map((item) => (
          <NavLink
            key={item.to}
            to={item.to}
            end={item.to === '/'}
            className={({ isActive }) => `soc-sidebar__link${isActive ? ' soc-sidebar__link--active' : ''}`}
          >
            <span className="soc-sidebar__link-code" aria-hidden="true">{item.code}</span>
            <span>{item.label}</span>
          </NavLink>
        ))}
      </nav>
      <div className="soc-sidebar__footer">Industrial monitoring workspace</div>
    </aside>
  );
};

export default Sidebar;
