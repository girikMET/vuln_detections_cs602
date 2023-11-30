async function loadItems() {
    const response = await fetch('http://localhost:3000/items');
    const items = await response.json();
    const table = document.getElementById('vulnerabilityTable');
    table.innerHTML = '';
 
    let header = table.createTHead();
    let headerRow = header.insertRow(0);
    let headers = ["VulnerabilityID", "Severity", "PkgName", "InstalledVersion", "FixedVersion", "PublishedDate", "LastModifiedDate"];
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
          cell.textContent = item[header];
       });
    });
 }