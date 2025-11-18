import tkinter as tk
from tkinter import scrolledtext
import threading
import time
import subprocess
import os
import signal
import sys

# Define the path to your CLI script
FIREWALL_SCRIPT = "firewall.py"
LOG_FILE = "firewall.log"

class FirewallGUI:
    def __init__(self, master):
        self.master = master
        master.title("Python Personal Firewall Monitor")
        master.geometry("900x650")

        self.is_running = False
        self.log_update_thread = None
        self.log_file_path = os.path.join(os.getcwd(), LOG_FILE)
        
        # --- 1. Control Frame ---
        control_frame = tk.Frame(master, padx=10, pady=10, relief=tk.RIDGE, bd=2)
        control_frame.pack(fill='x', pady=5, padx=10)

        self.start_button = tk.Button(control_frame, text="▶ Start Monitor", command=self.start_monitor, bg='#28a745', fg='white', font=("Arial", 10, "bold"))
        self.start_button.pack(side=tk.LEFT, padx=10)

        self.stop_button = tk.Button(control_frame, text="■ Stop Monitor", command=self.stop_monitor, bg='#dc3545', fg='white', state=tk.DISABLED, font=("Arial", 10, "bold"))
        self.stop_button.pack(side=tk.LEFT, padx=10)

        self.status_label = tk.Label(control_frame, text="Status: Ready | Run as SUDO/Admin!", fg='blue', font=("Arial", 10))
        self.status_label.pack(side=tk.RIGHT, padx=10)
        
        # --- 2. Log Display ---
        tk.Label(master, text="Live Blocked Traffic Log", font=("Arial", 12, "bold")).pack(pady=5)
        self.log_area = scrolledtext.ScrolledText(master, wrap=tk.WORD, width=100, height=35, bg='#333333', fg='#00FF00', font=("Consolas", 10))
        self.log_area.pack(padx=10, pady=10)
        self.log_area.insert(tk.END, ">>> Ensure you run this GUI with 'sudo' or Administrator privileges.\n")
        self.log_area.see(tk.END)
        
    def start_monitor(self):
        """Starts the firewall.py CLI script as a subprocess."""
        if self.is_running: return

        self.status_label.config(text="Status: Starting...")
        
        try:
            # Clear the previous log file
            with open(self.log_file_path, 'w'): pass 
            self.log_area.delete(1.0, tk.END)

            # NOTE: We use 'sudo' here as a common prefix for Linux/macOS elevation
            cmd = ['sudo', sys.executable, FIREWALL_SCRIPT] 
            
            # Start the process. stdout/stderr can be useful for debugging startup issues.
            self.firewall_process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            self.is_running = True
            
            self.status_label.config(text="Status: Running", fg='green')
            self.start_button.config(state=tk.DISABLED)
            self.stop_button.config(state=tk.NORMAL)
            
            # Start thread to continuously read the log file
            self.log_update_thread = threading.Thread(target=self.update_log_area, daemon=True)
            self.log_update_thread.start()

        except FileNotFoundError:
            self.status_label.config(text="Status: Error - firewall.py not found!", fg='red')
            self.log_area.insert(tk.END, "Error: Make sure firewall.py exists.\n")
        except Exception as e:
            self.status_label.config(text=f"Status: Error - {e}", fg='red')
            self.log_area.insert(tk.END, f"Error starting process: {e}\n")


    def stop_monitor(self):
        """Stops the subprocess and cleanup."""
        if not self.is_running: return

        self.status_label.config(text="Status: Stopping...")

        if hasattr(self, 'firewall_process') and self.firewall_process:
            try:
                # Terminate the process gently
                self.firewall_process.send_signal(signal.SIGINT) # Send Ctrl+C equivalent
                self.firewall_process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                 self.firewall_process.kill() # Force kill if necessary
        
        self.is_running = False
        self.status_label.config(text="Status: Stopped", fg='red')
        self.start_button.config(state=tk.NORMAL)
        self.stop_button.config(state=tk.DISABLED)


    def update_log_area(self):
        """Thread function to read the log file and update the GUI."""
        while self.is_running:
            try:
                # Read the current content of the log file
                with open(self.log_file_path, 'r') as f:
                    content = f.read()
                
                # Schedule GUI update (Tkinter safety)
                self.master.after(0, lambda c=content: self._update_text_widget(c))

            except FileNotFoundError:
                pass
            except Exception:
                pass
            
            time.sleep(0.5) # Check for updates twice per second

    def _update_text_widget(self, content):
        """Helper to update the ScrolledText widget."""
        self.log_area.delete(1.0, tk.END)
        self.log_area.insert(tk.END, content)
        self.log_area.see(tk.END) # Auto-scroll to the bottom

    def on_closing(self):
        """Ensure subprocess is terminated when the window is closed."""
        self.stop_monitor()
        self.master.destroy()

if __name__ == "__main__":
    root = tk.Tk()
    app = FirewallGUI(root)
    root.protocol("WM_DELETE_WINDOW", app.on_closing)
    root.mainloop()
