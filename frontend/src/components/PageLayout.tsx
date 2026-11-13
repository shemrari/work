import Sidebar from './Sidebar';
import Header from './Header';

type PageLayoutProps = {
  children: React.ReactNode;
};

const PageLayout = ({ children }: PageLayoutProps) => {
  return (
    <div className="soc-app-shell">
      <Sidebar />
      <div className="soc-app-main">
        <Header />
        <main className="soc-page-content">{children}</main>
      </div>
    </div>
  );
};

export default PageLayout;
