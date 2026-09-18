import subprocess
import os

# session menager just autoamcticly turns on commands. 
# =======================================================================================
#                               CLIENT COMMANDS
#========================================================================================
HOSTS_PATH = os.path.join(os.environ['windir'], 'System32', 'drivers', 'etc', 'hosts')
ENTRY = "26.230.135.6 gosredirector.ea.com"

def add_entry(path, entry):
    with open(path, 'r') as file_handle:
        if(entry in file_handle.read()):
            return
    with open(path, 'a') as  file_handle :
        file_handle.write(f"\n{entry}\n")
    clearDNS()

def remove_entry(path, entry):
    # Najpierw wczytujemy linie do zmiennej
    with open(path, 'r') as file_handle:
        lines = file_handle.readlines()

    with open(path, 'w') as file_handle:
        for line in lines:
            if entry not in line:
                file_handle.write(line)
    clearDNS()


def clearDNS():
    result = subprocess.run(["ipconfig", "/flushdns"], capture_output=True)
    if result.returncode == 0:
        return True
    return False

# =======================================================================================
#                               HOST COMMANDS
#========================================================================================

# PS C:\Users\bar-t\OneDrive\Dokumenty\TurboRivals> python -u proto-lab\tls_terminator.py --public-ip 26.230.135.6 `
# >>   --entitlements online `
# >>   --local-persona "Bartek" `
# >>   --player 26.45.138.207=filip | Tee-Object log-66.txt

PATH = "../proto-lab/"
COMMAND = ["python", "-u", r"proto-lab\tls_terminator.py", "--public-ip", "26.230.135.6", "--entitlements", "online"]

class Game:
    def __init__(self):
        # Przypisujemy zmienne do instancji obiektu używając 'self.'
        self.player_count = 0
        self.list_players = []

    def get_player_count(self):
        return self.player_count

    def get_list_players(self):
        return self.list_players

    def addPlayer(self, nick_add, ip_add):
        current_players = self.get_list_players()
        
        if current_players:
            for player in current_players:
                ip, nick = player
                if ip == ip_add or nick == nick_add:
                    return False 

        self.list_players.append((ip_add, nick_add))
        self.player_count += 1
        return True

    def removePlayer(self, nick_remove): 
        current_players = self.get_list_players()
        
        for player in current_players:
            ip, nick = player
            if nick_remove == nick:
                self.list_players.remove(player)
                self.player_count -= 1
                break  
            
def buildCommand(entry, localName, listPlayers):
    """listPlayers must be a tuple of (name, ip)"""
    if len(listPlayers) > 5:
        return "too many players!"
    command = COMMAND.copy()
    command.extend(["--local-persona", localName])
    for player in listPlayers:
        ip, nick = player
        command.extend(["--player", f"{ip}={nick}"])
    return command

def runCommand(command):
    """returns kurde krotka stdout and stderr runs main comand of tls terminator"""
    proces = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    stdout, stderr = proces.communicate()
    return (stdout, stderr)





