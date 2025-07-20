document.addEventListener('DOMContentLoaded', () => {
    const searchInput = document.getElementById('projectSearch');
    const projectCards = document.querySelectorAll('.project-card');
    const downloadButtons = document.querySelectorAll('.download-button');
    searchInput.addEventListener('keyup', (event) => {
        const searchTerm = event.target.value.toLowerCase();
        projectCards.forEach(card => {
            const projectName = card.dataset.projectName.toLowerCase();
            if (projectName.includes(searchTerm)) {
                card.style.display = 'flex';
            } else {
                card.style.display = 'none';
            }
        });
    });
    downloadButtons.forEach(button => {
        button.addEventListener('click', () => {
            if (!button.disabled) {
                const projectId = button.dataset.projectId;
            }
        });
    });
});
