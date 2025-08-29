function toggleAvatarMenu() {
    document.getElementById("avatarMenu")?.classList.toggle("hidden");
}

function toggleNotificationMenu() {
    document.getElementById("notificationMenu")?.classList.toggle("hidden");
}

window.addEventListener('click', function (e) {
    const avatarBtn = document.querySelector('button[onclick="toggleAvatarMenu()"]');
    const avatarMenu = document.getElementById("avatarMenu");

    const notifBtn = document.querySelector('button[onclick="toggleNotificationMenu()"]');
    const notifMenu = document.getElementById("notificationMenu");

    if (avatarMenu && !avatarBtn.contains(e.target) && !avatarMenu.contains(e.target)) {
        avatarMenu.classList.add("hidden");
    }

    if (notifMenu && !notifBtn.contains(e.target) && !notifMenu.contains(e.target)) {
        notifMenu.classList.add("hidden");
    }
});

function toggleSidebar() {
    const sidebar = document.getElementById('sidebar');
    sidebar.classList.toggle('-translate-x-full');
}
