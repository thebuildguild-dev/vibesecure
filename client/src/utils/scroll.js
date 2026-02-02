export const scrollToTop = ({ delay = 0, smooth = true } = {}) => {
  const scroll = () => {
    try {
      window.scrollTo({
        top: 0,
        left: 0,
        behavior: smooth ? "smooth" : "auto",
      });
    } catch {
      document.documentElement.scrollTop = 0;
      document.body.scrollTop = 0;
    }
  };

  if (delay > 0) {
    setTimeout(scroll, delay);
  } else {
    requestAnimationFrame(scroll);
  }
};
