async function loadItems() {
    const response = await fetch('http://localhost:3000/items');
    const items = await response.json();
    const table = document.getElementById('vulnerabilityTable');
    table.innerHTML = '';
    let header = table.createTHead();
    let headerRow = header.insertRow(0);
    let headers = ["VulnerabilityID", "Severity", "PkgName", "InstalledVersion", "FixedVersion", "PublishedDate", "LastModifiedDate", "Actions"];
    headers.forEach((header, index) => {
       let th = document.createElement('th');
       th.textContent = header;
       headerRow.appendChild(th);
    });
 
    let tbody = table.createTBody();
    items.forEach(item => {
       let row = tbody.insertRow();
       headers.forEach(header => {
          let cell = row.insertCell();
          if (header === 'VulnerabilityID') {
             let a = document.createElement('a');
             a.textContent = item[header];
             a.href = '#';
             a.onclick = () => openLinkSelectionDialog(item[header]);
             cell.appendChild(a);
          } else if (header === 'Actions') {
             let editButton = document.createElement('button');
             editButton.textContent = 'Edit';
             editButton.onclick = () => editItem(item);
             cell.appendChild(editButton);
 
             let deleteButton = document.createElement('button');
             deleteButton.textContent = 'Delete';
             deleteButton.onclick = () => deleteItem(item.VulnerabilityID);
             cell.appendChild(deleteButton);
          } else {
             cell.textContent = item[header];
          }
       });
    });
 }
 
 function openLinkSelectionDialog(vulnerabilityId) {
    const choice = confirm("Open in NVD? Click 'Cancel' for Mitre.");
    if (choice) {
       window.open(`https://nvd.nist.gov/vuln/detail/${vulnerabilityId}`, "_blank");
    } else {
       window.open(`https://cve.mitre.org/cgi-bin/cvename.cgi?name=${vulnerabilityId}`, "_blank");
    }
 }
 
 function editItem(item) {
    let updatedSeverity = prompt("Enter new severity for " + item.VulnerabilityID, item.Severity);
    if (updatedSeverity) {
       updateItem(item.VulnerabilityID, {
          ...item,
          Severity: updatedSeverity
       });
    }
 }
 
 async function updateItem(vulnerabilityId, updatedData) {
    if (updatedData._id) {
       delete updatedData._id;
    }
    try {
       const response = await fetch(`http://localhost:3000/items/${vulnerabilityId}`, {
          method: 'PUT',
          headers: {
             'Content-Type': 'application/json',
          },
          body: JSON.stringify(updatedData)
       });
 
       if (response.ok) {
          loadItems();
       } else {
          const errorData = await response.json();
          console.error('Error updating the item:', errorData);
          alert(`Error updating the item: ${errorData.message}`);
       }
    } catch (error) {
       console.error('Network or other error:', error);
       alert('Failed to update the item. Please check the console for more details.');
    }
 }
 
 async function deleteItem(vulnerabilityId) {
    if (confirm("Are you sure you want to delete this item?")) {
       const response = await fetch(`http://localhost:3000/items/${vulnerabilityId}`, {
          method: 'DELETE'
       });
       if (response.ok) {
          loadItems();
       } else {
          alert("Error deleting the item");
       }
    }
 }