function loadContent(url) {
console.log('Loading content from:', url);  // Debugging log
fetch(url)
    .then(response => {
        if (!response.ok) {
            throw new Error('Network response was not ok');
        }
        return response.text();
    })
    .then(data => {
        document.getElementById('content').innerHTML = data;
    })
    .catch(error => {
        console.error('Error loading content:', error);
        document.getElementById('content').innerHTML = '<p>Failed to load content. Please try again.</p>';
    });
}

function setActiveLink(clickedLink) {
    var sidebarLinks = document.querySelectorAll('.sidebar ul li nav');
    sidebarLinks.forEach(link => {
        link.classList.remove('active');
    });
    clickedLink.classList.add('active');
}

function handleClick(url, clickedLink) {
loadContent(url);
setActiveLink(clickedLink);
}

function toggleDropdown(dropdownId) {
const dropdown = document.getElementById(dropdownId);
dropdown.style.display = dropdown.style.display === 'block' ? 'none' : 'block';
}

function handleSubmit(event) {
    event.preventDefault(); // Prevent form submission
    var form = event.target;
    var formData = new FormData(form);

    fetch('/folders', {
        method: 'POST',
        body: formData
    })
    .then(response => response.text())
    .then(data => {
        // Update the table with the new content
        document.getElementById('folders-body').innerHTML = data;
    })
    .catch(error => {
        console.error('Error:', error);
    });
}
// Ensure the correct link is active based on current URL
document.addEventListener('DOMContentLoaded', () => {
    const currentPath = window.location.pathname;
    const links = document.querySelectorAll('.sidebar a');
    links.forEach(link => {
        if (link.getAttribute('href') === currentPath) {
            link.classList.add('active');
        }
    });
});
// Function to handle form submission and redirect
function handleFormSubmit(event) {
    event.preventDefault(); // Prevent the default form submission

    var form = event.target;
    var formData = new FormData(form);

    fetch(form.action, {
        method: 'POST',
        body: formData
    })
    .then(response => response.text())
    .then(data => {
        // Redirect to the "Passwords" page
        window.location.href = '/passwords'; // Adjust the path as needed
    })
    .catch(error => {
        console.error('Error:', error);
        alert('Failed to save. Please try again.');
    });
}

// Add event listener to handle form submission
document.addEventListener('DOMContentLoaded', () => {
    const form = document.getElementById('myForm');
    if (form) {
        form.addEventListener('submit', handleFormSubmit);
    }
});
function deleteFolder(url, rowElement) {
    fetch(url, {
        method: 'POST'
    })
    .then(response => response.text())
    .then(data => {
        // Update the table with the received HTML
        document.getElementById('folders-body').innerHTML = data;
    })
    .catch(error => {
        console.error('Error:', error);
    });
}

function downloadTableAsCSV() {
    var table = document.getElementById("passwords-table");
    var rows = table.rows;
    var csvContent = "";

    for (var i = 0; i < rows.length; i++) {
        var row = rows[i];
        var cells = row.cells;
        var rowContent = [];

        for (var j = 0; j < cells.length; j++) {
            rowContent.push(cells[j].innerText);
        }

        csvContent += rowContent.join(",") + "\n";
    }

    var blob = new Blob([csvContent], { type: 'text/csv' });
    var url = window.URL.createObjectURL(blob);
    var a = document.createElement("a");
    a.setAttribute("href", url);
    a.setAttribute("download", "table.csv");
    a.click();
}
function downloadTableAsPDF() {
    // Access jsPDF from the jspdf module
    const { jsPDF } = window.jspdf;

    // Create a new jsPDF instance
    var doc = new jsPDF('p', 'pt', 'a4');

    var table = document.getElementById("passwords-table");

    // Fetch the table headers
    var headers = [];
    var headerCells = table.querySelectorAll("thead th");
    headerCells.forEach(function(headerCell) {
        headers.push(headerCell.innerText);
    });

    // Fetch the table rows
    var rows = [];
    var tableRows = table.querySelectorAll("tbody tr");
    tableRows.forEach(function(row) {
        var rowData = [];
        var cells = row.querySelectorAll("td");
        cells.forEach(function(cell) {
            rowData.push(cell.innerText);
        });
        rows.push(rowData);
    });

    // Generate PDF with autoTable
    doc.autoTable({
        head: [headers],
        body: rows,
        theme: 'grid',
        startY: 20,
        margin: { top: 20 },
        styles: { fontSize: 10, cellPadding: 5, overflow: 'linebreak' },
        headStyles: { fillColor: [60, 141, 188], textColor: 255, fontStyle: 'bold' }
    });

    // Save the generated PDF
    doc.save("table.pdf");
}

function openPopup(name) {
    fetch('/pwd/' + name)
        .then(response => response.text())
        .then(html => {
            document.getElementById('popupContent').innerHTML = html;
            document.getElementById('popup').style.display = 'flex';
        });
}

function closePopup() {
    document.getElementById('popup').style.display = 'none';
}
function togglePopup() {
    document.getElementById("popup").classList.toggle("active");
}
function showModal() {
    document.querySelector(".overlay").style.display = "block"; // Show the overlay
    document.querySelector(".modal-box").style.display = "block"; // Show the modal
}

function hideModal() {
    document.querySelector(".overlay").style.display = "none"; // Hide the overlay
    document.querySelector(".modal-box").style.display = "none"; // Hide the modal
}
function toggleDropdown(event) {
    var dropdownContent = event.currentTarget.nextElementSibling;
    dropdownContent.classList.toggle('show');
}

window.onclick = function(event) {
    if (!event.target.matches('.action_dropbtn')) {
        var dropdowns = document.querySelectorAll('.dropdown-content');
        dropdowns.forEach(function (dropdownContent) {
            if (dropdownContent.classList.contains('show')) {
                dropdownContent.classList.remove('show');
            }
        });
    }
}
function fetchPasswordStrength() {
    console.log('Fetching password strength...'); // Debug statement
    fetch('/calculate_overall_strength')
        .then(response => response.json())
        .then(data => {
            console.log('Fetched strength data:', data); // Debug statement
            if (data.strength !== undefined) {
                let strength = data.strength;
                let circularProgress = document.querySelector(".circular-progress");
                let progressValue = document.querySelector(".progress-value");

                if (circularProgress && progressValue) {
                    console.log('Updating circular progress and progress value'); // Debug statement
                    progressValue.textContent = `${strength.toFixed(2)}%`;
                    circularProgress.style.background = `conic-gradient(#FD7401 ${strength * 3.6}deg, #ededed ${strength * 3.6}deg)`;
                } else {
                    console.error('Circular progress or progress value elements not found');
                }
            } else {
                console.error('Error fetching strength:', data.error);
            }
        })
        .catch(error => {
            console.error('Error:', error);
        });
}


function handleClickDashboard(route, element) {
    // Update the active state of the sidebar link
    document.querySelectorAll('.sidebar .nav').forEach(nav => nav.classList.remove('active'));
    element.classList.add('active');

    // Fetch the new content and update the content area
    fetch(route)
        .then(response => response.text())
        .then(html => {
            console.log('Fetched HTML:', html); // Debugging output
            // Update the content of the page
            document.getElementById('content').innerHTML = html;

            // After content is updated, ensure the dashboard specific logic is run
            if (route === '/dashboard') {
                // Use requestAnimationFrame to ensure DOM update has been rendered
                //requestAnimationFrame(() => {
                    console.log('Loading dashboard content...');
                    fetchChartData(); // Separate function for fetching chart data
                //});
            }
        })
        .catch(error => console.error('Error fetching content:', error));
}

function fetchChartData() {
    // Fetch chart data separately
    fetch('/dashboard/data')
        .then(response => response.json())
        .then(data => {
            if (data.error) {
                console.error('Error fetching chart data:', data.error);
                document.getElementById('chart-container').innerHTML = '<p>Error loading chart data.</p>';
                return;
            }
            const chartData = {
                labels: data.labels || [],
                values: data.values || [],
                colors: data.colors || []
            };
            console.log('Fetched chart data:', chartData); // Debugging chart data
            renderChart(chartData.labels, chartData.values, chartData.colors);
        })
        .catch(error => {
            console.error('Error fetching chart data:', error);
            document.getElementById('chart-container').innerHTML = '<p>Error loading chart data.</p>';
        });
}
function renderChart(labels, values, colors) {
    const total = values.reduce((sum, val) => sum + val, 0); // Calculate the total count of passwords

    const canvas = document.getElementById('passwordStrengthChart');
    if (canvas) {
        const ctx = canvas.getContext('2d');
        new Chart(ctx, {
            type: 'polarArea', // Set chart type to polarArea
            data: {
                labels: labels,
                datasets: [{
                    data: values,
                    backgroundColor: colors,
                }]
            },
            options: {
                responsive: true,
                plugins: {
                    tooltip: {
                        callbacks: {
                            label: function(tooltipItem) {
                                const count = values[tooltipItem.dataIndex];
                                const percentage = Math.round((count / total) * 100); // Round off
                                const label = labels[tooltipItem.dataIndex];
                                return `${label}: ${count} (${percentage}%)`; // Return label with count and percentage
                            }
                        }
                    }
                },
                scales: {
                    r: { // Radius scale configuration
                        ticks: {
                            display: false // Optionally hide radial axis labels (adjust if needed)
                        }
                    }
                }
            }
        });
    } else {
        console.error('Canvas element not found for the chart.');
    }
}

function restoreAll(url) {
    if (confirm("Are you sure you want to restore all items?")) {
        fetch(url, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/x-www-form-urlencoded'
            },
        })
        .then(response => response.text())
        .then(data => {
            alert('All items restored successfully.');
            location.reload(); // Reload the page to reflect changes
        })
        .catch(error => {
            console.error('Error:', error);
            alert('An error occurred while restoring items.');
        });
    }
}

function deleteAll(url) {
    if (confirm("Are you sure you want to delete all items?")) {
        fetch(url, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/x-www-form-urlencoded'
            },
        })
        .then(response => response.text())
        .then(data => {
            alert('All items deleted successfully.');
            location.reload(); // Reload the page to reflect changes
        })
        .catch(error => {
            console.error('Error:', error);
            alert('An error occurred while deleting items.');
        });
    }
}

function handleSelectedItems(actionUrl, isRestore = true) {
    const selectedCheckboxes = document.querySelectorAll('tbody input[type="checkbox"]:checked');
    const selectedItemIds = Array.from(selectedCheckboxes).map(checkbox => checkbox.value);

    if (selectedItemIds.length === 0) {
        alert(`No items selected for ${isRestore ? 'restoration' : 'deletion'}.`);
        return;
    }

    if (confirm(`Are you sure you want to ${isRestore ? 'restore' : 'delete'} the selected items?`)) {
        fetch(actionUrl, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({ item_ids: selectedItemIds }) // Sending selected item IDs as JSON
        })
        .then(response => {
            if (response.ok) {
                return response.text();
            } else {
                throw new Error('Network response was not ok.');
            }
        })
        .then(data => {
            alert(`Selected items ${isRestore ? 'restored' : 'deleted'} successfully.`);
            location.reload(); // Reload the page to reflect changes
        })
        .catch(error => {
            console.error('Error:', error);
            alert(`An error occurred while ${isRestore ? 'restoring' : 'deleting'} items.`);
        });
    }
}

function deletePassword(url, rowElement) {
    // Confirm the deletion
    if (confirm('Are you sure you want to delete this password?')) {
        // Send a request to the server to delete the password
        fetch(url, {
            method: 'POST'
        })
        .then(response => {
            if (response.ok) {
                // Remove the row from the table
                rowElement.remove();
            } else {
                alert('Failed to delete password.');
            }
        })
        .catch(error => {
            console.error('Error:', error);
        });
    }
}        

// Function to update button text based on checkbox selection
function updateButtonText() {
    var checkboxes = document.querySelectorAll('tbody input[type="checkbox"]');
    var anyChecked = Array.from(checkboxes).some(checkbox => checkbox.checked);
    var restoreButton = document.getElementById('restore-btn');
    var deleteButton = document.getElementById('delete-btn');

    if (anyChecked) {
        restoreButton.textContent = 'Restore Selected';
        restoreButton.setAttribute('onclick', "handleSelectedItems('/restore_selected', true)");
        deleteButton.textContent = 'Delete Selected';
        deleteButton.setAttribute('onclick', "handleSelectedItems('/delete_selected', false)");
    } else {
        restoreButton.textContent = 'Restore All';
        restoreButton.setAttribute('onclick', "restoreAll('/restore_all')");
        deleteButton.textContent = 'Delete All';
        deleteButton.setAttribute('onclick', "deleteAll('/delete_all')");
    }
}
function toggleDropdown() {
    const dropdown = document.querySelector('.dropdown-container-add');
    const tableContainer = document.querySelector('.table-container');

    if (dropdown.classList.contains('dropdown-open')) {
        // Remove 'dropdown-open' class and move table up
        dropdown.classList.remove('dropdown-open');
        tableContainer.style.marginTop = '30px'; // Reset table position
    } else {
        // Add 'dropdown-open' class and move table down
        dropdown.classList.add('dropdown-open');
        tableContainer.style.marginTop = '100px'; // Push table down
    }
}
// Show and hide rename modal
function showRenameModal(currentFolderName, folderElement) {
    document.getElementById('rename_folder_name').value = currentFolderName;  // Pre-fill the current name
    document.getElementById('current_folder_name').value = currentFolderName;  // Store current folder name
    document.getElementById('renameModal').folderElement = folderElement;  // Store folder element to update later
    document.querySelector("#renameModal").style.display = "block";
}

function hideRenameModal() {
    document.querySelector("#renameModal").style.display = "none";
}

function submitRename(event) {
    event.preventDefault();

    const newFolderName = document.getElementById('rename_folder_name').value;
    const currentFolderName = document.getElementById('current_folder_name').value;

    // Prepare the form data
    const formData = new FormData();
    formData.append('new_folder_name', newFolderName);

    fetch(`/rename_folder/${currentFolderName}`, {
        method: 'POST',
        body: formData
    })
    .then(response => {
        if (response.ok) {
            // Update the folder name in the table
            const folderElement = document.getElementById('renameModal').folderElement;

            if (folderElement) {
                const linkElement = folderElement.querySelector('a'); // Get the <a> element inside the folder row
                if (linkElement) {
                    linkElement.textContent = newFolderName;  // Update the displayed folder name
                    linkElement.setAttribute('onclick', `loadContent('/folder_form/${newFolderName}')`);  // Update the onclick action
                }
            }

            hideRenameModal();
        } else {
            throw new Error('Failed to rename folder');
        }
    })
    .catch(error => {
        console.error(error);
        alert('Error renaming folder.');
    });
}

function searchTable() {
    const search = document.querySelector('.search-container input[name="search"]');
    const table_rows = document.querySelectorAll('tbody tr');

    let search_data = search.value.toLowerCase();

    table_rows.forEach((row, i) => {
        let table_data = row.textContent.toLowerCase();
        row.classList.toggle('hide', table_data.indexOf(search_data) < 0);
        row.style.setProperty('--delay', i / 25 + 's');
    });

    document.querySelectorAll('tbody tr:not(.hide)').forEach((visible_row, i) => {
        visible_row.style.backgroundColor = (i % 2 === 0) ? 'transparent' : '#0000000b';
    });
}
// Sorting function
function sortColumn(column) {
    let table = document.querySelector('tbody');
    let rows = Array.from(table.querySelectorAll('tr'));
    let sort_asc = !table.getAttribute('data-sort-asc') || table.getAttribute('data-sort-asc') === 'false';
    table.setAttribute('data-sort-asc', sort_asc);

    rows.sort((a, b) => {
        let first = a.querySelectorAll('td')[column].textContent.toLowerCase();
        let second = b.querySelectorAll('td')[column].textContent.toLowerCase();

        if (sort_asc) {
            return first.localeCompare(second);
        } else {
            return second.localeCompare(first);
        }
    });

    rows.forEach(row => table.appendChild(row));
}
function togglePassword() {
    const password = document.getElementById('pwd');
    const toggleIcon = document.getElementById('togglePassword');

    // Toggle the type attribute
    const type = password.getAttribute('type') === 'password' ? 'text' : 'password';
    password.setAttribute('type', type);

    // Toggle the eye and eye-slash icon
    toggleIcon.classList.toggle('fa-eye-slash');
}
function copyToClipboard(id) {
    const copyText = document.getElementById(id);
    copyText.select();
    copyText.setSelectionRange(0, 99999);
    document.execCommand("copy");
    const message = document.getElementById('usernameMessage');
    message.innerText = "Copied the username!";
    message.style.display = "block"; // Show the message
    setTimeout(() => message.style.display = "none", 2000); // Hide after 2 seconds
}

function copyPassword() {
    const passwordField = document.getElementById('pwd');
    const password = passwordField.value;

    const tempInput = document.createElement('input');
    tempInput.value = password;
    document.body.appendChild(tempInput);
    tempInput.select();
    document.execCommand("copy");
    document.body.removeChild(tempInput);

    const message = document.getElementById('passwordMessage');
    message.innerText = "Copied the password!";
    message.style.display = "block"; // Show the message
    setTimeout(() => message.style.display = "none", 2000); // Hide after 2 seconds
}
