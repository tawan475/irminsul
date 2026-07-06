import re
import subprocess
import sys
import os

def update_cargo_toml(cargo_toml):
    if not os.path.exists(cargo_toml):
        print(f"Error: {cargo_toml} not found.")
        return

    with open(cargo_toml, "r") as f:
        content = f.read()

    lines = content.split('\n')
    new_lines = []
    updated = False

    for line in lines:
        match = re.search(r'git\s*=\s*"([^"]+)"', line)
        if match:
            url = match.group(1)
            print(f"Fetching latest rev for {url}...")
            try:
                res = subprocess.run(["git", "ls-remote", url, "HEAD"], capture_output=True, text=True, check=True)
                if not res.stdout.strip():
                    print(f"Warning: No HEAD found for {url}")
                    new_lines.append(line)
                    continue
                latest_rev = res.stdout.split()[0]
            except Exception as e:
                print(f"Failed to fetch rev for {url}: {e}")
                new_lines.append(line)
                continue
                
            # Check if rev already exists in this line
            if re.search(r'rev\s*=\s*"[^"]+"', line):
                # Replace existing rev
                new_line = re.sub(r'(rev\s*=\s*")[^"]+(")', rf'\g<1>{latest_rev}\g<2>', line)
            else:
                # Append rev before the closing brace
                new_line = re.sub(r'(\s*})\s*$', rf', rev = "{latest_rev}"\g<1>', line)
                
            if new_line != line:
                print(f"Updated {url} to rev {latest_rev[:8]}")
                line = new_line
                updated = True
            else:
                print(f"{url} is already up to date at {latest_rev[:8]}")
            
        new_lines.append(line)

    if updated:
        with open(cargo_toml, "w") as f:
            f.write('\n'.join(new_lines))
        print(f"\nSuccessfully updated {cargo_toml}!")
    else:
        print(f"\nEverything is already up-to-date in {cargo_toml}.")

if __name__ == "__main__":
    target_toml = sys.argv[1] if len(sys.argv) > 1 else "Cargo.toml"
    update_cargo_toml(target_toml)
