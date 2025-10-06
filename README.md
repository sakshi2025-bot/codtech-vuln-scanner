# codtech-vuln-scanner

*COMPANY*: CODTECH IT SOLUTIONS  

*NAME*: SAKSHI NAGARAJ MASHETTY

*INTERN ID*: CT06DY1830

*DOMAIN*: CYBERSECURITY AND ETHICAL HACKING 

*DURATION*: 4 WEEKS 

*MENTOR*: NEELA SANTHOSH

🌐 Task 2: Web Application Vulnerability Scanner

The Web Application Vulnerability Scanner is a Python-based security assessment tool designed to detect common vulnerabilities in web applications automatically. It focuses on identifying potential threats such as Cross-Site Scripting (XSS) and SQL Injection (SQLi) — two of the most frequently exploited weaknesses in web systems. The project aims to enhance web security awareness and provide developers and security testers with a simple yet effective way to analyze and secure their web applications.

🎯 Objective

The primary objective of this task is to build a lightweight vulnerability scanner that can:

Crawl a target web application and analyze its pages.

Identify HTML forms, parameters, and input fields that can be potential attack vectors.

Test these inputs for vulnerabilities like reflected XSS and SQL injection.

Generate a detailed vulnerability report in JSON format for further analysis.

This scanner serves as an educational tool to demonstrate the concepts of ethical hacking, secure coding, and automated web vulnerability detection.

⚙️ Working Process

Initialization
The scanner starts by accepting a target URL from the user. It fetches the HTML content of the web application using Python’s HTTP libraries and begins analyzing its structure.

Crawling and Input Detection
The tool searches for forms and query parameters on each page. It records important attributes such as form actions, input names, and methods (GET or POST).

Vulnerability Testing

Cross-Site Scripting (XSS) Detection:
The scanner injects harmless test payloads (markers) into form fields or query parameters. It then checks if the same payload appears in the response, indicating a reflected XSS vulnerability.

SQL Injection (SQLi) Detection:
The tool appends special characters like ', ", or -- to input parameters and observes the response for error patterns related to SQL databases, such as syntax or query errors. These patterns signal possible SQL injection points.

Reporting Results
Once scanning is complete, the findings are saved into a report.json file. This report includes:

The target URL

Number of pages scanned

Details of detected forms

Identified vulnerabilities with their parameters and affected pages
The report provides a structured summary that can be used for documentation, debugging, or penetration testing analysis.

🛠️ Technologies Used

Language: Python

Libraries: requests, BeautifulSoup (bs4), argparse, json, and re

Output Format: JSON (for easy readability and integration with other tools)

💡 Key Features

Detects reflected XSS vulnerabilities.

Identifies potential SQL injection flaws.

Automatically scans forms and URL query parameters.

Saves structured scan reports for documentation and analysis.

Lightweight, extensible, and suitable for educational use.

🧠 Applications and Use Cases

This tool can be used by:

Developers to test their web apps for vulnerabilities before deployment.

Cybersecurity students to learn about web attacks and ethical hacking.

Security analysts as a quick auditing utility during initial assessments.

The scanner is purely intended for educational and authorized security testing. It helps users understand the importance of secure coding and proactive vulnerability detection.

🏁 Conclusion

The Web Application Vulnerability Scanner successfully demonstrates how Python can be used to automate the detection of web security weaknesses. By implementing real-world scanning techniques, it provides hands-on experience with vulnerability testing concepts such as input validation, payload injection, and response analysis.

This project emphasizes the importance of cybersecurity awareness and showcases a practical solution to identify and mitigate potential threats in web applications. The resulting tool is simple, efficient, and highly educational — making it a valuable contribution to secure software development practices.

#OUTPUT 
<img width="1920" height="1020" alt="Image" src="https://github.com/user-attachments/assets/6d4d60db-e16f-4621-a1cf-7ff424d564f6" />

<img width="1920" height="1020" alt="Image" src="https://github.com/user-attachments/assets/86a60d21-e9b1-45c9-9d5c-02740fc4ccf2" />
