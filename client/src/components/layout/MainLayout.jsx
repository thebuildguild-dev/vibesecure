import Navbar from "./Navbar";
import Footer from "./Footer";


export default function MainLayout({ children, showProfile = true }) {
  return (
    <div className="min-h-screen flex flex-col">
      <Navbar showProfile={showProfile} />
      <main className="flex-1">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-6 sm:py-8">
          {children}
        </div>
      </main>
      <Footer />
    </div>
  );
}
