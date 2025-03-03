1. Install dan Masuk ke Virtual Environment (venv)
Install venv (jika belum terinstall) : pip install virtualenv, 
Buat Virtual Environment: python -m venv venv, 
Aktifkan Virtual Environment: source venv/bin/activate

2. Clone Repository dari GitHub:
git clone https://github.com/sintapermatasari/SecuriScan.git, 
cd SecuriScan

3. Install wkhtmltopdf
wkhtmltopdf adalah alat untuk mengonversi HTML menjadi PDF:
sudo apt update, 
sudo apt install wkhtmltopdf

5. Install Dependencies dengan pip :
pip install Flask==2.2.3 requests==2.28.2 python-whois==0.8.0 pdfkit==0.6.1
