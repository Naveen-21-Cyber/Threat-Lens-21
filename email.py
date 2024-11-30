import tkinter as tk
from tkinter import ttk, messagebox, simpledialog, filedialog
import re
import json
from datetime import datetime
import random


emails = [
    {"sender": "no-reply@bank.com", "subject": "Your bank account is locked!", 
     "body": "Click here to unlock: http://fakebank.com\nUrgent action required to prevent account suspension.", 
     "is_phishing": True},
    {"sender": "hr@company.com", "subject": "Meeting Reminder", 
     "body": "Don't forget our meeting at 3 PM today.\nPlease confirm your attendance.", 
     "is_phishing": False},
    {"sender": "lottery@winner.com", "subject": "You've won a prize!", 
     "body": "Claim your prize at http://scam.com\nImmediate action required to collect your winnings.", 
     "is_phishing": True},
    {"sender": "accounts@company.com", "subject": "Invoice Attached", 
     "body": "Please find your invoice attached. Let me know if you have questions.", 
     "is_phishing": False},
    {"sender": "security@paypal.com", "subject": "Unusual Login Attempt Detected", 
     "body": "Review the login attempt here: http://scam-paypal.com\nYour account security is at risk!", 
     "is_phishing": True},
    {"sender": "support@linkedin.com", "subject": "Connection Request", 
     "body": "You have a new connection request from a professional contact.\nVisit LinkedIn to review and accept.", 
     "is_phishing": False},
    {"sender": "security@amazzon-verify.com", "subject": "Urgent Account Verification", 
     "body": "Your Amazon account will be suspended. Verify immediately at: http://amazzon-secure.net\nComplete verification in next 24 hours.", 
     "is_phishing": True},
    {"sender": "updates@github.com", "subject": "Repository Activity Report", 
     "body": "Here's a summary of recent activity in your GitHub repositories.\nCheck your dashboard for details.", 
     "is_phishing": False},
    {"sender": "winner@lottery-claims.com", "subject": "Congratulations! Large Prize", 
     "body": "You've won a substantial cash prize! Claim now at: http://lottery-claim.org\nProvide personal details to receive winnings.", 
     "is_phishing": True},
    {"sender": "notifications@dropbox.com", "subject": "File Sharing Update", 
     "body": "A file has been shared with you. Log in to your Dropbox account to view.", 
     "is_phishing": False},
         {"sender": "no-reply@bank.com", "subject": "Your bank account is locked!", 
     "body": "Click here to unlock: http://fakebank.com\nUrgent action required to prevent account suspension.", 
     "is_phishing": True},
    {"sender": "hr@company.com", "subject": "Meeting Reminder", 
     "body": "Don't forget our meeting at 3 PM today.\nPlease confirm your attendance.", 
     "is_phishing": False},
    {"sender": "lottery@winner.com", "subject": "You've won a prize!", 
     "body": "Claim your prize at http://scam.com\nImmediate action required to collect your winnings.", 
     "is_phishing": True},
    {"sender": "accounts@company.com", "subject": "Invoice Attached", 
     "body": "Please find your invoice attached. Let me know if you have questions.", 
     "is_phishing": False},
    {"sender": "security@paypal.com", "subject": "Unusual Login Attempt Detected", 
     "body": "Review the login attempt here: http://scam-paypal.com\nYour account security is at risk!", 
     "is_phishing": True},
]
user_responses = []



def show_email_content():
    selected_index = email_listbox.curselection()
    if selected_index:
        index = selected_index[0]
        email = emails[index]
        email_content.delete("1.0", tk.END)
        

        email_content.insert(
            tk.END,
            f"Sender: {email['sender']}\n"
            f"Subject: {email['subject']}\n\n"
            f"{email['body']}\n"
        )
    else:
        messagebox.showinfo("Info", "Select an email to view its content.")

# Mark phishing
def mark_phishing():
    selected_index = email_listbox.curselection()
    if selected_index:
        index = selected_index[0]
        user_responses.append((index, True))
        messagebox.showinfo("Info", "Email marked as phishing!")
    else:
        messagebox.showinfo("Info", "Select an email to mark.")

# Mark safe
def mark_safe():
    selected_index = email_listbox.curselection()
    if selected_index:
        index = selected_index[0]
        user_responses.append((index, False))
        messagebox.showinfo("Info", "Email marked as safe!")
    else:
        messagebox.showinfo("Info", "Select an email to mark.")

# Submit results
def submit_results():
    if not user_responses:
        messagebox.showwarning("Warning", "You haven't analyzed any emails yet!")
        return

    correct = 0
    detailed_feedback = []
    phishing_emails = 0
    safe_emails = 0
    
    # Categorize and analyze responses
    for response in user_responses:
        index, user_choice = response
        email = emails[index]
        
        # Track total phishing and safe emails
        if email["is_phishing"]:
            phishing_emails += 1
        else:
            safe_emails += 1
        
        # Determine if the user's response was correct
        is_correct = email["is_phishing"] == user_choice
        if is_correct:
            correct += 1
        
        # Generate detailed feedback for each email
        feedback_entry = {
            "subject": email["subject"],
            "sender": email["sender"],
            "actual_status": "Phishing" if email["is_phishing"] else "Safe",
            "user_status": "Phishing" if user_choice else "Safe",
            "is_correct": is_correct
        }
        
        # Provide explanation for incorrect classifications
        explanation = ""
        if not is_correct:
            if email["is_phishing"]:
                explanation = "Missed Phishing Detection: This email contains suspicious characteristics."
                explanation += "\nKey Red Flags:"
                if "http://" in email["body"]:
                    explanation += "\n- Suspicious URL detected"
                if "urgent" in email["body"].lower() or "action required" in email["body"].lower():
                    explanation += "\n- Urgency tactics used"
                if "winner" in email["subject"].lower() or "prize" in email["subject"].lower():
                    explanation += "\n- Unrealistic promise of rewards"
            else:
                explanation = "False Phishing Alarm: This was a legitimate email."
                explanation += "\nWhy it's Safe:"
                explanation += "\n- Comes from a professional email address"
                explanation += "\n- Neutral, professional language"
                explanation += "\n- No suspicious links or urgent demands"
        
        feedback_entry["explanation"] = explanation
        detailed_feedback.append(feedback_entry)

    total = len(user_responses)
    score = (correct / total) * 100
    
    # Create results window with comprehensive feedback
    results_window = tk.Toplevel(root)
    results_window.title("Phishing Simulation Detailed Results")
    results_window.geometry("700x600")
    
    # Summary Frame
    summary_frame = tk.Frame(results_window)
    summary_frame.pack(pady=10)
    
    tk.Label(summary_frame, text="Phishing Simulation Analysis", font=("Helvetica", 16, "bold")).pack()
    tk.Label(summary_frame, text=f"Total Emails Analyzed: {total}", font=("Helvetica", 12)).pack()
    tk.Label(summary_frame, text=f"Correctly Identified: {correct}", font=("Helvetica", 12)).pack()
    tk.Label(summary_frame, text=f"Score: {score:.2f}%", font=("Helvetica", 14, "bold")).pack()
    
    # Detailed Performance Metrics
    metrics_frame = tk.Frame(results_window)
    metrics_frame.pack(pady=10)
    
    tk.Label(metrics_frame, text="Performance Breakdown", font=("Helvetica", 12, "bold")).pack()
    tk.Label(metrics_frame, text=f"Phishing Emails: {phishing_emails}", font=("Helvetica", 10)).pack()
    tk.Label(metrics_frame, text=f"Safe Emails: {safe_emails}", font=("Helvetica", 10)).pack()
    
    # Detailed Feedback Text Widget
    feedback_frame = tk.Frame(results_window)
    feedback_frame.pack(pady=10, expand=True, fill="both")
    
    feedback_label = tk.Label(feedback_frame, text="Email Analysis Details:", font=("Helvetica", 12, "bold"))
    feedback_label.pack()
    
    feedback_text_widget = tk.Text(feedback_frame, height=20, width=80, wrap=tk.WORD)
    feedback_text_widget.pack(expand=True, fill="both")
    
    # Populate detailed feedback
    for entry in detailed_feedback:
        status_color = "green" if entry["is_correct"] else "red"
        feedback_text_widget.tag_config("correct", foreground="green")
        feedback_text_widget.tag_config("incorrect", foreground="red")
        
        feedback_text_widget.insert(tk.END, f"Subject: {entry['subject']}\n", "header")
        feedback_text_widget.insert(tk.END, f"Sender: {entry['sender']}\n", "header")
        feedback_text_widget.insert(tk.END, 
            f"Actual Status: {entry['actual_status']} | Your Identification: {entry['user_status']}\n", 
            "correct" if entry["is_correct"] else "incorrect"
        )
        
        if not entry["is_correct"]:
            feedback_text_widget.insert(tk.END, "\nDetailed Explanation:\n", "header")
            feedback_text_widget.insert(tk.END, f"{entry['explanation']}\n\n", "explanation")
    
    feedback_text_widget.config(state=tk.DISABLED)
    
    # Export Results Button (Same as before)
    def export_results():
        file_path = filedialog.asksaveasfilename(defaultextension=".txt")
        if file_path:
            with open(file_path, "w") as f:
                f.write("Phishing Simulation Detailed Results\n")
                f.write(f"Total Emails: {total}\n")
                f.write(f"Correctly Identified: {correct}\n")
                f.write(f"Score: {score:.2f}%\n\n")
                f.write("Detailed Email Analysis:\n")
                for entry in detailed_feedback:
                    f.write(f"Subject: {entry['subject']}\n")
                    f.write(f"Sender: {entry['sender']}\n")
                    f.write(f"Actual Status: {entry['actual_status']} | Your Identification: {entry['user_status']}\n")
                    if not entry["is_correct"]:
                        f.write(f"Explanation: {entry['explanation']}\n")
                    f.write("\n")
            messagebox.showinfo("Export", f"Results exported to {file_path}")
    
    export_button = tk.Button(results_window, text="Export Detailed Results", command=export_results)
    export_button.pack(pady=10)

# Add a new email - Enhanced version
def add_email():
    # Create a new top-level window for adding emails
    add_email_window = tk.Toplevel(root)
    add_email_window.title("Add New Email")
    add_email_window.geometry("500x500")
    
    # Sender input
    tk.Label(add_email_window, text="Sender Email:").pack()
    sender_entry = tk.Entry(add_email_window, width=50)
    sender_entry.pack(pady=5)

    # Subject input
    tk.Label(add_email_window, text="Email Subject:").pack()
    subject_entry = tk.Entry(add_email_window, width=50)
    subject_entry.pack(pady=5)

    # Body input
    tk.Label(add_email_window, text="Email Body:").pack()
    body_text = tk.Text(add_email_window, height=10, width=50)
    body_text.pack(pady=5)

    # Phishing status
    tk.Label(add_email_window, text="Is this a phishing email?").pack()
    phishing_var = tk.BooleanVar()
    phishing_checkbox = tk.Checkbutton(add_email_window, text="Phishing", variable=phishing_var)
    phishing_checkbox.pack(pady=5)

    # Submit function for the new email
    def submit_new_email():
        sender = sender_entry.get()
        subject = subject_entry.get()
        body = body_text.get("1.0", tk.END).strip()
        is_phishing = phishing_var.get()

        if sender and subject and body:
            new_email = {
                "sender": sender, 
                "subject": subject, 
                "body": body, 
                "is_phishing": is_phishing
            }
            emails.append(new_email)
            email_listbox.insert(tk.END, f"{subject} - {sender}")
            messagebox.showinfo("Success", "New email added successfully!")
            add_email_window.destroy()
        else:
            messagebox.showerror("Error", "Please fill in all fields.")

    # Submit button
    submit_button = tk.Button(
        add_email_window, 
        text="Add Email", 
        command=submit_new_email
    )
    submit_button.pack(pady=10)

# Main GUI setup
root = tk.Tk()
root.title("Email Phishing Simulation")
root.geometry("700x600")

# Header
header_frame = tk.Frame(root, pady=10, bg="#34495e")
header_frame.pack(fill="x")
header_label = tk.Label(
    header_frame, 
    text="Email Phishing Simulation", 
    font=("Helvetica", 16, "bold"), 
    fg="#ecf0f1", 
    bg="#34495e"
)
header_label.pack()
instruction_label = tk.Label(
    header_frame, 
    text="Select an email to view its content and mark it as phishing or safe.", 
    font=("Helvetica", 12), 
    fg="#ecf0f1", 
    bg="#34495e"
)
instruction_label.pack()

# Email listbox
email_listbox_frame = ttk.LabelFrame(root, text="Email Inbox", padding=10)
email_listbox_frame.pack(fill="both", expand=True, padx=10, pady=10)

email_listbox = tk.Listbox(
    email_listbox_frame, 
    height=15, 
    width=50, 
    bg="#ffffff", 
    fg="#2c3e50", 
    font=("Arial", 10)
)
email_scrollbar = tk.Scrollbar(email_listbox_frame, orient="vertical", command=email_listbox.yview)
email_listbox.config(yscrollcommand=email_scrollbar.set)

for email in emails:
    email_listbox.insert(tk.END, f"{email['subject']} - {email['sender']}")

email_listbox.grid(row=0, column=0, sticky="ns")
email_scrollbar.grid(row=0, column=1, sticky="ns")

# Center buttons 
button_frame = tk.Frame(root, pady=10)
button_frame.pack()

buttons = [
    ("Show Email Content", show_email_content, "#3498db"),   # Blue
    ("Mark as Phishing", mark_phishing, "#e74c3c"),          # Red
    ("Mark as Safe", mark_safe, "#2ecc71"),                  # Green
    ("Submit Results", submit_results, "#f39c12"),           # Orange
    ("Add Email", add_email, "#9b59b6")                      # Purple
]

for text, command, color in buttons:
    button = tk.Button(
        button_frame, 
        text=text, 
        command=command, 
        bg=color, 
        fg="white", 
        font=("Helvetica", 10, "bold"),
        padx=10,
        pady=5
    )
    button.pack(side=tk.LEFT, padx=5)

# Email content display
content_frame = ttk.LabelFrame(root, text="Email Content", padding=10)
content_frame.pack(fill="both", expand=True, padx=10, pady=10)

email_content = tk.Text(
    content_frame, 
    height=10, 
    wrap="word", 
    font=("Courier", 12), 
    bg="#ecf0f1", 
    fg="#2c3e50"
)
email_content.pack(fill="both", expand=True)

# Run the GUI loop
root.mainloop()