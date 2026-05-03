/**
 * 小猪智能体面板 - 公共导航栏
 * 所有页面统一引用此文件，自动渲染导航栏
 * 用法：在 </body> 前添加 <script src="navbar.js"></script>
 * 导航栏配置在此文件中统一管理，修改一处即可更新所有页面
 */
(function() {
    'use strict';

    // ===== 导航菜单配置（统一管理）=====
    var navItems = [
        { path: 'index.html',    icon: 'fa-th-large',  label: '仪表盘' },
        { path: 'models.html',   icon: 'fa-cube',      label: '模型管理' },
        { path: 'sessions.html', icon: 'fa-comments',  label: '会话管理' },
        { path: 'skills.html',   icon: 'fa-puzzle-piece', label: '技能管理' },
        { path: 'systems.html',  icon: 'fa-server',    label: '智能系统' },
        { path: 'changelog.html',icon: 'fa-history',   label: '更新日志' }
    ];

    // 当前页面
    var currentPage = window.location.pathname.split('/').pop() || 'index.html';

    // ===== 构建导航栏 HTML =====
    var menuHtml = '';
    var mobileMenuHtml = '';
    for (var i = 0; i < navItems.length; i++) {
        var item = navItems[i];
        var isActive = currentPage === item.path ? ' active' : '';
        menuHtml += '<a href="/' + item.path + '" class="navbar-item' + isActive + '"><i class="fas ' + item.icon + '"></i>' + item.label + '</a>';
        mobileMenuHtml += '<a href="/' + item.path + '" class="mobile-menu-item' + isActive + '"><i class="fas ' + item.icon + '"></i>' + item.label + '</a>';
    }

    var navbarHTML =
        '<nav class="navbar">' +
            '<a href="/index.html" class="navbar-brand">' +
                '<div class="logo"><i class="fas fa-robot"></i></div>' +
                '<span>小猪智能体面板</span>' +
            '</a>' +
            '<div class="navbar-menu">' + menuHtml + '</div>' +
            '<div class="navbar-right">' +
                '<button class="theme-toggle" id="themeToggle" title="切换日/夜间模式">' +
                    '<i class="fas fa-sun icon-sun"></i>' +
                    '<i class="fas fa-moon icon-moon"></i>' +
                '</button>' +
                '<div class="navbar-status"><div class="pulse"></div>系统运行中</div>' +
                '<button class="hamburger" id="hamburgerBtn" title="菜单">' +
                    '<i class="fas fa-bars"></i>' +
                '</button>' +
            '</div>' +
        '</nav>' +
        '<div class="mobile-menu" id="mobileMenu">' + mobileMenuHtml + '</div>';

    // ===== 渲染导航栏 =====
    // 先移除任何已存在的导航栏（包括内联的和动态渲染的）
    var existingNavs = document.querySelectorAll('nav.navbar, #mobileMenu, #navbar-container');
    for (var i = 0; i < existingNavs.length; i++) {
        existingNavs[i].parentNode.removeChild(existingNavs[i]);
    }

    // 在 body 最前面插入导航栏
    var wrapper = document.createElement('div');
    wrapper.innerHTML = navbarHTML;
    while (wrapper.firstChild) {
        document.body.insertBefore(wrapper.firstChild, document.body.firstChild);
    }

    // ===== 绑定交互事件 =====
    // 汉堡菜单
    var hamburger = document.getElementById('hamburgerBtn');
    var mobileMenu = document.getElementById('mobileMenu');
    if (hamburger && mobileMenu) {
        hamburger.addEventListener('click', function() {
            mobileMenu.classList.toggle('open');
        });
        var items = mobileMenu.querySelectorAll('.mobile-menu-item');
        for (var i = 0; i < items.length; i++) {
            items[i].addEventListener('click', function() {
                mobileMenu.classList.remove('open');
            });
        }
        document.addEventListener('click', function(e) {
            if (!mobileMenu.contains(e.target) && !hamburger.contains(e.target)) {
                mobileMenu.classList.remove('open');
            }
        });
    }

    // 主题切换
    var htmlEl = document.documentElement;
    var themeToggle = document.getElementById('themeToggle');

    function applyTheme(theme) {
        if (theme === 'light') {
            htmlEl.setAttribute('data-theme', 'light');
        } else {
            htmlEl.removeAttribute('data-theme');
        }
    }

    function getPreferredTheme() {
        var stored = localStorage.getItem('nexus-theme');
        if (stored === 'light' || stored === 'dark') return stored;
        return window.matchMedia('(prefers-color-scheme: light)').matches ? 'light' : 'dark';
    }

    applyTheme(getPreferredTheme());

    window.matchMedia('(prefers-color-scheme: light)').addEventListener('change', function(e) {
        if (!localStorage.getItem('nexus-theme')) {
            applyTheme(e.matches ? 'light' : 'dark');
        }
    });

    if (themeToggle) {
        themeToggle.addEventListener('click', function() {
            var next = htmlEl.getAttribute('data-theme') === 'light' ? 'dark' : 'light';
            applyTheme(next);
            localStorage.setItem('nexus-theme', next);
        });
    }
})();
