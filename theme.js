(function () {
    const STORAGE_KEY = 'saman-healthcare-theme';
    const root = document.documentElement;

    const setTheme = (theme) => {
        const value = theme === 'dark' ? 'dark' : 'light';
        root.dataset.theme = value;

        try {
            localStorage.setItem(STORAGE_KEY, value);
        } catch (error) {
            // Ignore storage issues and keep the theme in the DOM only.
        }

        const toggles = document.querySelectorAll('[data-theme-toggle]');
        toggles.forEach((button) => {
            const label = button.querySelector('.theme-toggle-label');
            const nextLabel = value === 'dark' ? 'Light mode' : 'Dark mode';
            button.setAttribute('aria-label', `Switch to ${value === 'dark' ? 'light' : 'dark'} mode`);
            button.title = `Switch to ${value === 'dark' ? 'light' : 'dark'} mode`;
            if (label) label.textContent = nextLabel;
        });
    };

    const getPreferredTheme = () => {
        try {
            const savedTheme = localStorage.getItem(STORAGE_KEY);
            if (savedTheme === 'dark' || savedTheme === 'light') {
                return savedTheme;
            }
        } catch (error) {
            // Ignore storage issues and fall back to the system preference.
        }

        return window.matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light';
    };

    const initTheme = () => {
        const theme = getPreferredTheme();
        setTheme(theme);

        document.querySelectorAll('[data-theme-toggle]').forEach((button) => {
            button.addEventListener('click', () => {
                const nextTheme = root.dataset.theme === 'dark' ? 'light' : 'dark';
                setTheme(nextTheme);
            });
        });
    };

    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', initTheme);
    } else {
        initTheme();
    }
})();
