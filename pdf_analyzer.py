#!/usr/bin/env python3
"""
PDF Security Intelligence Platform with Dictionary Attack
Advanced offensive security tool for PDF analysis and password cracking
"""

import os
import sys
import time
import itertools
from datetime import datetime
from pathlib import Path

try:
    import PyPDF2
    import pdfplumber
    from reportlab.lib.pagesizes import letter
    from reportlab.pdfgen import canvas
    import io
    import tkinter as tk
    from tkinter import filedialog, messagebox, simpledialog
except ImportError as e:
    print("❌ Missing dependencies. Please install requirements:")
    print("pip install -r requirements.txt")
    sys.exit(1)

class PDFPasswordCracker:
    def __init__(self):
        self.attempts = 0
        self.start_time = None
        self.found_password = None
    
    def try_password(self, file_path, password):
        """Try to decrypt PDF with given password"""
        try:
            with open(file_path, 'rb') as file:
                pdf_reader = PyPDF2.PdfReader(file)
                if pdf_reader.decrypt(password):
                    self.found_password = password
                    return True
        except Exception:
            pass
        return False
    
    def load_dictionary_file(self, dict_file_path):
        """Load passwords from dictionary file"""
        try:
            with open(dict_file_path, 'r', encoding='utf-8', errors='ignore') as f:
                passwords = [line.strip() for line in f if line.strip()]
            print(f"📚 Loaded {len(passwords)} passwords from dictionary file")
            return passwords
        except Exception as e:
            print(f"❌ Error loading dictionary file: {str(e)}")
            return None
    
    def dictionary_attack(self, file_path, wordlist):
        """Try passwords from a wordlist"""
        print("🔓 Starting dictionary attack...")
        self.start_time = time.time()
        self.attempts = 0
        
        for password in wordlist:
            self.attempts += 1
            password = password.strip()
            
            if self.attempts % 100 == 0:
                print(f"⏳ Attempts: {self.attempts}, Current: {password}")
            
            if self.try_password(file_path, password):
                elapsed = time.time() - self.start_time
                print(f"✅ Password found: '{password}' after {self.attempts} attempts in {elapsed:.2f} seconds")
                return password
        
        return None
    
    def brute_force_attack(self, file_path, charset, max_length=4):
        """Brute force attack with character set"""
        print(f"🔓 Starting brute force attack (max length: {max_length})...")
        self.start_time = time.time()
        self.attempts = 0
        
        for length in range(1, max_length + 1):
            for candidate in itertools.product(charset, repeat=length):
                password = ''.join(candidate)
                self.attempts += 1
                
                if self.attempts % 1000 == 0:
                    print(f"⏳ Attempts: {self.attempts}, Current: {password}")
                
                if self.try_password(file_path, password):
                    elapsed = time.time() - self.start_time
                    print(f"✅ Password found: '{password}' after {self.attempts} attempts in {elapsed:.2f} seconds")
                    return password
        
        return None

class PDFSecurityAnalyzer:
    def __init__(self):
        self.analysis_data = {}
        self.decrypted_file_path = None
        self.cracker = PDFPasswordCracker()
    
    def crack_pdf_password(self, file_path, dict_file_path=None):
        """Crack PDF password using dictionary attack and brute force"""
        print("🎯 Starting PDF password cracking...")
        
        # Try dictionary attack first
        if dict_file_path and os.path.exists(dict_file_path):
            print("📚 Using custom dictionary file...")
            custom_wordlist = self.cracker.load_dictionary_file(dict_file_path)
            if custom_wordlist:
                password = self.cracker.dictionary_attack(file_path, custom_wordlist)
                if password:
                    return password
        
        # If no custom dictionary or it failed, try built-in common passwords
        print("🔑 Trying built-in common passwords...")
        common_passwords = [
            "password", "123456", "12345678", "1234", "qwerty", "12345",
            "dragon", "baseball", "football", "letmein", "monkey",
            "696969", "abc123", "mustang", "michael", "shadow",
            "master", "jennifer", "111111", "2000", "jordan",
            "superman", "harley", "1234567", "freedom", "matrix",
            "company123", "admin", "test", "hello", "secret",
            "password123", "123", "admin123", "welcome", "login",
            "pass", "123abc", "123qwe", "admin@123", "password1"
        ]
        
        password = self.cracker.dictionary_attack(file_path, common_passwords)
        if password:
            return password
        
        # If dictionary attacks fail, try brute force
        print("🔢 Dictionary attack failed. Starting brute force...")
        charset = "abcdefghijklmnopqrstuvwxyz0123456789"
        password = self.cracker.brute_force_attack(file_path, charset, max_length=4)
        
        if password:
            return password
        else:
            print("❌ Password not found with current methods")
            return None
    
    def decrypt_pdf(self, file_path, password):
        """Decrypt PDF file with provided password"""
        print(f"🔓 Attempting to decrypt with password: {password}")
        
        try:
            with open(file_path, 'rb') as file:
                pdf_reader = PyPDF2.PdfReader(file)
                
                if pdf_reader.is_encrypted:
                    if pdf_reader.decrypt(password):
                        print("✅ PDF decrypted successfully!")
                        
                        # Create decrypted version
                        pdf_writer = PyPDF2.PdfWriter()
                        
                        for page_num in range(len(pdf_reader.pages)):
                            pdf_writer.add_page(pdf_reader.pages[page_num])
                        
                        # Save decrypted file
                        decrypted_path = file_path.replace('.pdf', '_decrypted.pdf')
                        with open(decrypted_path, 'wb') as output_file:
                            pdf_writer.write(output_file)
                        
                        self.decrypted_file_path = decrypted_path
                        return decrypted_path
                    else:
                        print("❌ Incorrect password")
                        return None
                else:
                    print("ℹ️ PDF is not encrypted")
                    self.decrypted_file_path = file_path
                    return file_path
                    
        except Exception as e:
            print(f"❌ Decryption error: {str(e)}")
            return None
    
    def extract_metadata(self, file_path):
        """Extract comprehensive metadata from PDF"""
        print("🔍 Extracting metadata...")
        metadata = {}
        
        try:
            with open(file_path, 'rb') as file:
                pdf_reader = PyPDF2.PdfReader(file)
                pdf_info = pdf_reader.metadata
                
                if pdf_info:
                    metadata = {
                        'title': getattr(pdf_info, 'title', 'N/A'),
                        'author': getattr(pdf_info, 'author', 'N/A'),
                        'subject': getattr(pdf_info, 'subject', 'N/A'),
                        'creator': getattr(pdf_info, 'creator', 'N/A'),
                        'producer': getattr(pdf_info, 'producer', 'N/A'),
                        'creation_date': str(getattr(pdf_info, 'creation_date', 'N/A')),
                        'modification_date': str(getattr(pdf_info, 'modification_date', 'N/A')),
                    }
                
                # Additional PDF info
                metadata.update({
                    'number_of_pages': len(pdf_reader.pages),
                    'is_encrypted': pdf_reader.is_encrypted,
                    'pdf_version': pdf_reader.pdf_header
                })
                
        except Exception as e:
            print(f"⚠️ Metadata extraction error: {str(e)}")
            metadata = {'error': str(e)}
        
        return metadata
    
    def extract_text_content(self, file_path):
        """Extract text content from PDF"""
        print("📝 Extracting text content...")
        text_content = {
            'visible_text': '',
            'hidden_text_blocks': [],
            'total_pages': 0
        }
        
        try:
            with pdfplumber.open(file_path) as pdf:
                text_content['total_pages'] = len(pdf.pages)
                
                for page_num, page in enumerate(pdf.pages):
                    page_text = page.extract_text()
                    if page_text:
                        text_content['visible_text'] += f"\n--- Page {page_num + 1} ---\n{page_text}\n"
                    
                    # Look for hidden elements
                    if page.chars:
                        hidden_chars = [char for char in page.chars if char.get('size', 0) < 2]
                        if hidden_chars:
                            text_content['hidden_text_blocks'].append({
                                'page': page_num + 1,
                                'count': len(hidden_chars),
                                'sample': ''.join([char['text'] for char in hidden_chars[:10]]) + '...' if hidden_chars else ''
                            })
        
        except Exception as e:
            print(f"⚠️ Text extraction error: {str(e)}")
            text_content['error'] = str(e)
        
        return text_content
    
    def analyze_security_issues(self, file_path, metadata):
        """Analyze PDF for security vulnerabilities"""
        print("⚠️ Analyzing security issues...")
        issues = []
        
        try:
            with open(file_path, 'rb') as file:
                pdf_reader = PyPDF2.PdfReader(file)
                
                # Check for JavaScript
                if '/JS' in pdf_reader.trailer.get('/Root', {}):
                    issues.append({
                        'type': 'CRITICAL',
                        'description': 'JavaScript detected in PDF - potential malicious code',
                        'risk': 'HIGH'
                    })
                
                # Check for auto-action triggers
                if '/OpenAction' in pdf_reader.trailer.get('/Root', {}):
                    issues.append({
                        'type': 'WARNING', 
                        'description': 'Auto-action configured - may execute automatically',
                        'risk': 'MEDIUM'
                    })
                
                # Check metadata for sensitive information
                sensitive_keywords = ['confidential', 'secret', 'password', 'internal', 'project']
                for key, value in metadata.items():
                    if isinstance(value, str):
                        for keyword in sensitive_keywords:
                            if keyword in value.lower():
                                issues.append({
                                    'type': 'INFO',
                                    'description': f'Sensitive keyword "{keyword}" found in {key}',
                                    'risk': 'LOW'
                                })
                                break
                
                # Check encryption strength
                if pdf_reader.is_encrypted:
                    issues.append({
                        'type': 'INFO',
                        'description': 'PDF is password protected',
                        'risk': 'MEDIUM'
                    })
                else:
                    issues.append({
                        'type': 'WARNING',
                        'description': 'PDF is not encrypted - data may be exposed',
                        'risk': 'MEDIUM'
                    })
        
        except Exception as e:
            print(f"⚠️ Security analysis error: {str(e)}")
            issues.append({
                'type': 'ERROR',
                'description': f'Analysis error: {str(e)}',
                'risk': 'UNKNOWN'
            })
        
        return issues
    
    def calculate_risk_level(self, issues):
        """Calculate overall risk level based on found issues"""
        if not issues:
            return 'LOW'
        
        risk_scores = {'CRITICAL': 3, 'WARNING': 2, 'INFO': 1, 'ERROR': 1}
        total_score = sum(risk_scores.get(issue['type'], 0) for issue in issues)
        
        if total_score >= 3:
            return 'HIGH'
        elif total_score >= 2:
            return 'MEDIUM'
        else:
            return 'LOW'
    
    def analyze_pdf(self, file_path, password=None, dict_file_path=None):
        """Comprehensive PDF security analysis with password cracking"""
        print(f"🔒 Starting PDF Security Analysis for: {file_path}")
        print("=" * 50)
        
        start_time = time.time()
        
        # Step 1: Handle PDF decryption
        working_file = file_path
        
        if not password:
            print("🎯 Attempting to crack PDF password...")
            cracked_password = self.crack_pdf_password(file_path, dict_file_path)
            if cracked_password:
                working_file = self.decrypt_pdf(file_path, cracked_password)
                password = cracked_password
            else:
                print("❌ Password cracking failed. Cannot proceed with analysis.")
                return None
        else:
            working_file = self.decrypt_pdf(file_path, password)
        
        if not working_file:
            print("❌ Could not access PDF content")
            return None
        
        # Step 2: Extract metadata
        print("🔍 Starting comprehensive security analysis...")
        metadata = self.extract_metadata(working_file)
        
        # Step 3: Extract text content
        text_content = self.extract_text_content(working_file)
        
        # Step 4: Analyze security issues
        security_issues = self.analyze_security_issues(working_file, metadata)
        
        # Step 5: Calculate risk level
        risk_level = self.calculate_risk_level(security_issues)
        
        # Compile analysis results
        self.analysis_data = {
            'file_info': {
                'filename': os.path.basename(file_path),
                'file_size': os.path.getsize(file_path),
                'analysis_date': datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                'analysis_duration': round(time.time() - start_time, 2),
                'password_cracked': password is not None and password != '',
                'cracking_attempts': self.cracker.attempts,
                'found_password': self.cracker.found_password,
                'dictionary_used': dict_file_path is not None
            },
            'metadata': metadata,
            'text_content': text_content,
            'security_issues': security_issues,
            'risk_assessment': {
                'level': risk_level,
                'issues_count': len(security_issues),
                'critical_count': len([i for i in security_issues if i['type'] == 'CRITICAL']),
                'warning_count': len([i for i in security_issues if i['type'] == 'WARNING'])
            },
            'decrypted_file': self.decrypted_file_path
        }
        
        print("✅ Analysis complete!")
        return self.analysis_data
    
    def generate_html_report(self, output_path="security_report.html"):
        """Generate comprehensive HTML security report"""
        print("📊 Generating professional HTML report...")
        
        analysis = self.analysis_data
        
        # HTML template with embedded CSS and JavaScript
        html_content = f"""
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>PDF Security Intelligence Report</title>
    <style>
        * {{
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }}
        
        body {{
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            line-height: 1.6;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
            padding: 20px;
        }}
        
        .container {{
            max-width: 1200px;
            margin: 0 auto;
            background: white;
            border-radius: 15px;
            box-shadow: 0 20px 40px rgba(0,0,0,0.1);
            overflow: hidden;
        }}
        
        .header {{
            background: linear-gradient(135deg, #2c3e50 0%, #3498db 100%);
            color: white;
            padding: 40px;
            text-align: center;
        }}
        
        .header h1 {{
            font-size: 2.5em;
            margin-bottom: 10px;
        }}
        
        .header .subtitle {{
            font-size: 1.2em;
            opacity: 0.9;
        }}
        
        .summary-section {{
            background: #f8f9fa;
            padding: 30px;
            border-bottom: 1px solid #e9ecef;
        }}
        
        .risk-badge {{
            display: inline-block;
            padding: 8px 20px;
            border-radius: 25px;
            font-weight: bold;
            margin: 10px 0;
        }}
        
        .risk-high {{
            background: #dc3545;
            color: white;
        }}
        
        .risk-medium {{
            background: #ffc107;
            color: black;
        }}
        
        .risk-low {{
            background: #28a745;
            color: white;
        }}
        
        .section {{
            padding: 30px;
            border-bottom: 1px solid #e9ecef;
        }}
        
        .section-title {{
            font-size: 1.5em;
            color: #2c3e50;
            margin-bottom: 20px;
            padding-bottom: 10px;
            border-bottom: 2px solid #3498db;
        }}
        
        .info-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
            gap: 20px;
            margin-top: 20px;
        }}
        
        .info-card {{
            background: #f8f9fa;
            padding: 20px;
            border-radius: 10px;
            border-left: 4px solid #3498db;
        }}
        
        .info-card h3 {{
            color: #2c3e50;
            margin-bottom: 10px;
        }}
        
        .metadata-table {{
            width: 100%;
            border-collapse: collapse;
            margin-top: 15px;
        }}
        
        .metadata-table th,
        .metadata-table td {{
            padding: 12px;
            text-align: left;
            border-bottom: 1px solid #ddd;
        }}
        
        .metadata-table th {{
            background: #3498db;
            color: white;
        }}
        
        .metadata-table tr:nth-child(even) {{
            background: #f8f9fa;
        }}
        
        .vulnerability-list {{
            list-style: none;
        }}
        
        .vulnerability-list li {{
            padding: 15px;
            margin: 10px 0;
            background: #fff3cd;
            border-left: 4px solid #ffc107;
            border-radius: 5px;
        }}
        
        .vulnerability-list .critical {{
            background: #f8d7da;
            border-left-color: #dc3545;
        }}
        
        .vulnerability-list .warning {{
            background: #fff3cd;
            border-left-color: #ffc107;
        }}
        
        .vulnerability-list .info {{
            background: #d1ecf1;
            border-left-color: #17a2b8;
        }}
        
        .recommendation-card {{
            background: #d1edff;
            padding: 20px;
            border-radius: 10px;
            margin: 15px 0;
            border-left: 4px solid #17a2b8;
        }}
        
        .footer {{
            text-align: center;
            padding: 30px;
            background: #2c3e50;
            color: white;
        }}
        
        .timestamp {{
            color: #6c757d;
            font-size: 0.9em;
            margin-top: 10px;
        }}
        
        .tech-info {{
            background: #e9ecef;
            padding: 15px;
            border-radius: 5px;
            font-family: monospace;
            margin-top: 10px;
        }}
        
        .hidden-content {{
            background: #f8f9fa;
            border: 1px solid #dee2e6;
            border-radius: 5px;
            padding: 15px;
            margin: 10px 0;
            max-height: 200px;
            overflow-y: auto;
        }}
        
        .password-info {{
            background: #d4edda;
            border: 1px solid #c3e6cb;
            border-radius: 5px;
            padding: 15px;
            margin: 10px 0;
        }}
        
        .cracking-info {{
            background: #fff3cd;
            border: 1px solid #ffeaa7;
            border-radius: 5px;
            padding: 15px;
            margin: 10px 0;
        }}
    </style>
</head>
<body>
    <div class="container">
        <!-- Header Section -->
        <div class="header">
            <h1>🔒 PDF Security Intelligence Report</h1>
            <p class="subtitle">Comprehensive Security Analysis & Vulnerability Assessment</p>
            <div class="timestamp">Generated on: {analysis['file_info']['analysis_date']}</div>
        </div>

        <!-- Executive Summary -->
        <div class="summary-section">
            <h2>Executive Summary</h2>
            <div class="risk-badge risk-{analysis['risk_assessment']['level'].lower()}">{analysis['risk_assessment']['level']} RISK ASSESSMENT</div>
            <p><strong>Target File:</strong> {analysis['file_info']['filename']}</p>
            <p><strong>File Size:</strong> {analysis['file_info']['file_size']} bytes</p>
            <p><strong>Analysis Summary:</strong> Found {analysis['risk_assessment']['issues_count']} security issues ({analysis['risk_assessment']['critical_count']} critical, {analysis['risk_assessment']['warning_count']} warnings)</p>
        """
        
        # Add password cracking info if applicable
        if analysis['file_info']['password_cracked']:
            html_content += f"""
            <div class="password-info">
                <h3>🔓 Password Successfully Cracked</h3>
                <p><strong>Password Found:</strong> <code>{analysis['file_info']['found_password']}</code></p>
                <p><strong>Cracking Attempts:</strong> {analysis['file_info']['cracking_attempts']}</p>
                <p><strong>Time Taken:</strong> {analysis['file_info']['analysis_duration']} seconds</p>
                <p><strong>Method:</strong> {'Dictionary Attack' if analysis['file_info']['dictionary_used'] else 'Brute Force Attack'}</p>
            </div>
            """
        
        html_content += """
        </div>

        <!-- File Intelligence -->
        <div class="section">
            <h2 class="section-title">📊 File Intelligence</h2>
            <div class="info-grid">
                <div class="info-card">
                    <h3>📄 Document Information</h3>
                    <p><strong>Filename:</strong> {analysis['file_info']['filename']}</p>
                    <p><strong>Size:</strong> {analysis['file_info']['file_size']} bytes</p>
                    <p><strong>Pages:</strong> {analysis['metadata'].get('number_of_pages', 'N/A')}</p>
                    <p><strong>Encrypted:</strong> {'Yes' if analysis['metadata'].get('is_encrypted') else 'No'}</p>
                </div>
                
                <div class="info-card">
                    <h3>🔍 Security Status</h3>
                    <p><strong>Risk Level:</strong> {analysis['risk_assessment']['level']}</p>
                    <p><strong>Vulnerabilities Found:</strong> {analysis['risk_assessment']['issues_count']}</p>
                    <p><strong>Critical Issues:</strong> {analysis['risk_assessment']['critical_count']}</p>
                    <p><strong>Analysis Time:</strong> {analysis['file_info']['analysis_duration']}s</p>
                </div>
                
                <div class="info-card">
                    <h3>🎯 Attack Vectors</h3>
                    <p>• Metadata Intelligence Gathering</p>
                    <p>• Hidden Data Extraction</p>
                    <p>• Document Structure Analysis</p>
                    <p>• Security Configuration Review</p>
                </div>
            </div>
        </div>

        <!-- Metadata Analysis -->
        <div class="section">
            <h2 class="section-title">🔍 Metadata Intelligence</h2>
            <table class="metadata-table">
                <thead>
                    <tr>
                        <th>Field</th>
                        <th>Value</th>
                        <th>Risk Level</th>
                    </tr>
                </thead>
                <tbody>
                    <tr>
                        <td><strong>Title</strong></td>
                        <td>{analysis['metadata'].get('title', 'N/A')}</td>
                        <td><span class="risk-badge risk-low">LOW</span></td>
                    </tr>
                    <tr>
                        <td><strong>Author</strong></td>
                        <td>{analysis['metadata'].get('author', 'N/A')}</td>
                        <td><span class="risk-badge risk-medium">MEDIUM</span></td>
                    </tr>
                    <tr>
                        <td><strong>Creator</strong></td>
                        <td>{analysis['metadata'].get('creator', 'N/A')}</td>
                        <td><span class="risk-badge risk-low">LOW</span></td>
                    </tr>
                    <tr>
                        <td><strong>Producer</strong></td>
                        <td>{analysis['metadata'].get('producer', 'N/A')}</td>
                        <td><span class="risk-badge risk-low">LOW</span></td>
                    </tr>
                    <tr>
                        <td><strong>Creation Date</strong></td>
                        <td>{analysis['metadata'].get('creation_date', 'N/A')}</td>
                        <td><span class="risk-badge risk-medium">MEDIUM</span></td>
                    </tr>
                    <tr>
                        <td><strong>Modification Date</strong></td>
                        <td>{analysis['metadata'].get('modification_date', 'N/A')}</td>
                        <td><span class="risk-badge risk-medium">MEDIUM</span></td>
                    </tr>
                </tbody>
            </table>
            
            <div class="tech-info">
                <strong>Intelligence Gathered:</strong> Document metadata can reveal author information, creation timelines, and software used - valuable for social engineering and targeted attacks.
            </div>
        </div>

        <!-- Security Vulnerabilities -->
        <div class="section">
            <h2 class="section-title">⚠️ Security Vulnerabilities</h2>
            <ul class="vulnerability-list">
        """
        
        # Add security issues
        for issue in analysis['security_issues']:
            risk_class = issue['type'].lower()
            html_content += f"""
                <li class="{risk_class}">
                    <strong>{issue['type']}:</strong> {issue['description']}
                </li>
            """
        
        html_content += """
            </ul>
        </div>
        """

        # Text Content Analysis
        html_content += f"""
        <!-- Text Content Analysis -->
        <div class="section">
            <h2 class="section-title">🔎 Content Analysis</h2>
            <div class="info-grid">
                <div class="info-card">
                    <h3>📝 Extracted Text</h3>
                    <div class="hidden-content">
                        {analysis['text_content'].get('visible_text', 'No text extracted')[:500] + '...' if len(analysis['text_content'].get('visible_text', '')) > 500 else analysis['text_content'].get('visible_text', 'No text extracted')}
                    </div>
                    <p><strong>Total Pages:</strong> {analysis['text_content'].get('total_pages', 0)}</p>
                </div>
                
                <div class="info-card">
                    <h3>🕵️ Hidden Content</h3>
        """
        
        if analysis['text_content'].get('hidden_text_blocks'):
            html_content += f"""
                    <p><strong>Hidden text blocks found:</strong> {len(analysis['text_content']['hidden_text_blocks'])}</p>
                    <div class="hidden-content">
            """
            for block in analysis['text_content']['hidden_text_blocks']:
                html_content += f"• Page {block['page']}: {block['sample']}<br>"
            html_content += "</div>"
        else:
            html_content += "<p>No hidden text blocks detected</p>"
        
        html_content += """
                </div>
            </div>
        </div>
        """

        # Security Recommendations
        html_content += f"""
        <!-- Security Recommendations -->
        <div class="section">
            <h2 class="section-title">🛡️ Security Recommendations</h2>
            
            <div class="recommendation-card">
                <h3>IMMEDIATE ACTIONS</h3>
                <p>• Review and sanitize PDF metadata before distribution</p>
                <p>• Implement document encryption for sensitive files</p>
                <p>• Remove any embedded JavaScript or auto-actions</p>
                <p>• Validate document contents for hidden information</p>
            </div>
            
            <div class="recommendation-card">
                <h3>PREVENTIVE MEASURES</h3>
                <p>• Establish document security policies</p>
                <p>• Use PDF sanitization tools before sharing</p>
                <p>• Train staff on secure document handling</p>
                <p>• Implement document classification system</p>
            </div>
        </div>

        <!-- Technical Details -->
        <div class="section">
            <h2 class="section-title">🔧 Technical Analysis Details</h2>
            <div class="tech-info">
                <strong>Analysis Tool:</strong> PDF Security Intelligence Platform v2.0<br>
                <strong>Scan Date:</strong> {analysis['file_info']['analysis_date']}<br>
                <strong>Scan Duration:</strong> {analysis['file_info']['analysis_duration']} seconds<br>
                <strong>PDF Version:</strong> {analysis['metadata'].get('pdf_version', 'N/A')}<br>
                <strong>Encryption Status:</strong> {'Encrypted' if analysis['metadata'].get('is_encrypted') else 'Not Encrypted'}<br>
        """
        
        if analysis['file_info']['password_cracked']:
            html_content += f"""
                <strong>Password Cracking:</strong> Successful ({analysis['file_info']['cracking_attempts']} attempts)<br>
                <strong>Found Password:</strong> {analysis['file_info']['found_password']}<br>
                <strong>Attack Method:</strong> {'Dictionary Attack' if analysis['file_info']['dictionary_used'] else 'Brute Force Attack'}<br>
            """
        
        html_content += """
                <strong>Tools Used:</strong> PyPDF2, pdfplumber, custom analysis scripts
            </div>
        </div>

        <!-- Footer -->
        <div class="footer">
            <p>Generated by PDF Security Intelligence Platform</p>
            <p>Offensive Security Tool - For Authorized Testing Only</p>
            <p>Report ID: PSI-{datetime.now().strftime("%Y%m%d")}-{hash(analysis['file_info']['filename']) % 10000}</p>
        </div>
    </div>

    <script>
        document.addEventListener('DOMContentLoaded', function() {{
            const riskBadges = document.querySelectorAll('.risk-badge');
            riskBadges.forEach(badge => {{
                badge.addEventListener('click', function() {{
                    alert('Risk assessment based on document content analysis and metadata exposure');
                }});
            }});
        }});
    </script>
</body>
</html>
        """
        
        # Write HTML file
        with open(output_path, 'w', encoding='utf-8') as f:
            f.write(html_content)
        
        print(f"✅ HTML report generated: {output_path}")
        return output_path

def create_demo_pdf():
    """Create a demo encrypted PDF for testing"""
    print("📄 Creating demo PDF file...")
    
    # Create a simple PDF with some content
    buffer = io.BytesIO()
    c = canvas.Canvas(buffer, pagesize=letter)
    
    # Add some content
    c.drawString(100, 750, "CONFIDENTIAL BUSINESS DOCUMENT")
    c.drawString(100, 730, "Project: Operation Phoenix")
    c.drawString(100, 710, "Author: john.smith@company.com")
    c.drawString(100, 690, "Date: 2024-01-15")
    c.drawString(100, 670, "Status: HIGHLY CONFIDENTIAL")
    c.drawString(100, 650, "Budget: $1,250,000")
    
    # Add some "hidden" text (very small)
    c.setFont("Helvetica", 2)
    c.drawString(10, 10, "HIDDEN: Internal note - CEO approval pending for budget increase")
    
    c.showPage()
    c.save()
    
    # Save the PDF
    demo_path = "demo_encrypted.pdf"
    with open(demo_path, 'wb') as f:
        f.write(buffer.getvalue())
    
    # Encrypt the PDF
    reader = PyPDF2.PdfReader(demo_path)
    writer = PyPDF2.PdfWriter()
    
    for page in reader.pages:
        writer.add_page(page)
    
    writer.encrypt("company123")
    
    with open(demo_path, "wb") as f:
        writer.write(f)
    
    print(f"✅ Encrypted demo PDF created: {demo_path}")
    
    # Create a sample dictionary file
    with open("sample_dictionary.txt", "w") as f:
        f.write("password\n123456\ncompany123\nadmin\ntest\nhello\nsecret\n")
    
    print("✅ Sample dictionary file created: sample_dictionary.txt")
    
    return demo_path

def choose_file_dialog(title, filetypes):
    """Open file chooser dialog"""
    root = tk.Tk()
    root.withdraw()
    file_path = filedialog.askopenfilename(title=title, filetypes=filetypes)
    return file_path

def ask_password():
    """Ask for PDF password using dialog"""
    root = tk.Tk()
    root.withdraw()
    password = simpledialog.askstring(
        "PDF Password", 
        "This PDF is encrypted. Enter the password:",
        show='*'
    )
    return password

def show_message(title, message):
    """Show message dialog"""
    root = tk.Tk()
    root.withdraw()
    messagebox.showinfo(title, message)

def main():
    """Main function to run the PDF security analysis"""
    print("🔒 PDF Security Intelligence Platform with Dictionary Attack")
    print("=" * 60)
    
    # Check if demo files exist, if not create them
    if not os.path.exists("demo_encrypted.pdf"):
        create_demo_pdf()
    
    # File selection
    print("📁 Please select a PDF file for analysis...")
    pdf_file = choose_file_dialog(
        "Select PDF File for Security Analysis",
        [("PDF files", "*.pdf"), ("All files", "*.*")]
    )
    
    if not pdf_file:
        # User cancelled file selection, use demo
        use_demo = messagebox.askyesno(
            "Demo File", 
            "No file selected. Would you like to use the demo PDF file?"
        )
        if use_demo:
            pdf_file = "demo_encrypted.pdf"
            print("Using demo PDF file")
        else:
            print("❌ No file selected. Exiting.")
            return
    
    if not os.path.exists(pdf_file):
        print(f"❌ File not found: {pdf_file}")
        show_message("Error", f"File not found: {pdf_file}")
        return
    
    # Check if PDF is encrypted
    try:
        with open(pdf_file, 'rb') as file:
            pdf_reader = PyPDF2.PdfReader(file)
            if pdf_reader.is_encrypted:
                print("🔐 PDF is encrypted")
                
                # Ask if user knows the password
                action = messagebox.askyesno(
                    "Encrypted PDF", 
                    "This PDF is encrypted.\n\nDo you know the password?\n\nClick 'No' to use dictionary attack."
                )
                
                if action:
                    # User knows password
                    password = ask_password()
                    dict_file_path = None
                else:
                    # User doesn't know password - ask for dictionary file
                    password = None
                    print("📚 Please select a dictionary file for password cracking...")
                    dict_file_path = choose_file_dialog(
                        "Select Dictionary File (Text file with passwords)",
                        [("Text files", "*.txt"), ("All files", "*.*")]
                    )
                    
                    if not dict_file_path:
                        use_sample = messagebox.askyesno(
                            "Dictionary File",
                            "No dictionary file selected. Use built-in common passwords?"
                        )
                        if use_sample:
                            dict_file_path = None
                            print("Using built-in common passwords...")
                        else:
                            print("❌ No dictionary file provided. Exiting.")
                            return
            else:
                password = None
                dict_file_path = None
                
    except Exception as e:
        print(f"❌ Error reading PDF: {str(e)}")
        show_message("Error", f"Could not read PDF file: {str(e)}")
        return
    
    # Initialize analyzer
    analyzer = PDFSecurityAnalyzer()
    
    # Perform analysis
    print("🔄 Starting comprehensive security analysis...")
    analysis_results = analyzer.analyze_pdf(pdf_file, password, dict_file_path)
    
    if analysis_results:
        # Generate HTML report
        report_path = analyzer.generate_html_report()
        
        # Print summary
        print("\n" + "=" * 50)
        print("📋 ANALYSIS SUMMARY")
        print("=" * 50)
        print(f"File: {analysis_results['file_info']['filename']}")
        print(f"Risk Level: {analysis_results['risk_assessment']['level']}")
        print(f"Security Issues: {analysis_results['risk_assessment']['issues_count']}")
        
        if analysis_results['file_info']['password_cracked']:
            print(f"🔓 Password Cracked: Yes - '{analysis_results['file_info']['found_password']}'")
            print(f"🔑 Attempts: {analyzer.cracker.attempts}")
            print(f"⏱️ Time: {analysis_results['file_info']['analysis_duration']} seconds")
        
        print(f"📄 Report: {report_path}")
        
        if analyzer.decrypted_file_path:
            print(f"💾 Decrypted File: {analyzer.decrypted_file_path}")
        
        # Show completion message
        message_text = f"PDF Security Analysis Complete!\n\nFile: {analysis_results['file_info']['filename']}\nRisk Level: {analysis_results['risk_assessment']['level']}\nIssues Found: {analysis_results['risk_assessment']['issues_count']}"
        
        if analysis_results['file_info']['password_cracked']:
            message_text += f"\nPassword Cracked: Yes - '{analysis_results['file_info']['found_password']}' ({analyzer.cracker.attempts} attempts)"
        
        message_text += f"\n\nReport saved as: {report_path}"
        
        show_message("Analysis Complete", message_text)
        
        print("\n🎯 Open the HTML report in your browser to view detailed analysis!")
        
        # Ask if user wants to open the report
        open_report = messagebox.askyesno("Open Report", "Would you like to open the security report now?")
        
        if open_report:
            try:
                if sys.platform == "win32":
                    os.startfile(report_path)
                elif sys.platform == "darwin":  # macOS
                    os.system(f"open {report_path}")
                else:  # Linux
                    os.system(f"xdg-open {report_path}")
            except Exception as e:
                print(f"⚠️ Could not open report automatically: {str(e)}")
                print(f"Please open manually: {report_path}")
                
    else:
        error_msg = "Analysis failed. Could not access PDF content."
        print(f"❌ {error_msg}")
        show_message("Error", error_msg)

if __name__ == "__main__":
    main()