const fs = require('fs');
const path = require('path');

const dir = __dirname;

console.log('📁 Klasördeki tüm dosyalar:\n');

const files = fs.readdirSync(dir);
files.forEach(file => {
  const fullPath = path.join(dir, file);
  const stat = fs.statSync(fullPath);
  
  if (stat.isDirectory()) {
    console.log(`📂 ${file}/`);
  } else {
    console.log(`📄 ${file}`);
  }
});

console.log(`\n✅ Toplam: ${files.length} dosya/klasör`);
