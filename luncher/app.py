import customtkinter as ctk
from PIL import Image
import os

ctk.set_appearance_mode("system")
ctk.set_default_color_theme("green") 

class TurboRivalsLauncher(ctk.CTk):
    def __init__(self):
        super().__init__()
        
        self.title("TurboRivals Launcher")
        self.geometry("840x600")
        self.resizable(False, False)
        BASE_DIR = os.path.dirname(os.path.abspath(__file__))
        sciezka_tla = os.path.join(BASE_DIR, "background.png")
        obraz = Image.open(sciezka_tla)
        self.tlo_image = ctk.CTkImage(light_image=obraz, dark_image=obraz, size=(840, 600))

        self.tlo_label = ctk.CTkLabel(self, text="", image=self.tlo_image)
        self.tlo_label.place(x=0, y=0, relwidth=1, relheight=1)



if __name__ == "__main__":
    app = TurboRivalsLauncher()
    app.mainloop()