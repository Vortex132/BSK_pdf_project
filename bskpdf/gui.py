import dearpygui.dearpygui as dpg

from bskpdf.crypto import Signer

signer = None

def _load_private_key():
    global signer
    path = dpg.get_value("private_key_input")
    password: str = dpg.get_value("private_key_pass")
    dpg.set_value("private_state", "")
    print(path, password)
    try:
        signer = Signer.from_file(path, password.encode())
        dpg.disable_item("public_key")
        dpg.enable_item("document")
        dpg.enable_item("sign_grp")
        dpg.set_value("private_state", f"Loaded {path}")
    except Exception as e:
        print(e)
        _clear_private_key()
        dpg.set_value("private_state", "Failed")

def _clear_private_key():
    global signer
    signer = None
    dpg.enable_item("public_key")
    dpg.disable_item("document")
    dpg.disable_item("sign_grp")
    dpg.set_value("private_state", "")

def _load_public_key():
    global signer
    path = dpg.get_value("public_key_input")
    dpg.set_value("public_state", "")
    print(path)
    try:
        signer = Signer.from_file_pub(path)
        dpg.disable_item("private_key")
        dpg.enable_item("document")
        dpg.set_value("public_state", f"Loaded {path}")
    except Exception as e:
        print(e)
        _clear_public_key()
        dpg.set_value("public_state", "Failed")

def _clear_public_key():
    global signer
    signer = None
    dpg.enable_item("private_key")
    dpg.disable_item("document")
    dpg.disable_item("sign_grp")
    dpg.set_value("public_state", "")

def _generate_keygen():
    signer = Signer.generate()
    path = dpg.get_value("keygen_input")
    password: str = dpg.get_value("keygen_pass")

    try:
        signer.to_file(path, password.encode())
        signer.to_file_pub(path + ".pub")
    except Exception as e:
        print(e)

def _sign():
    dpg.set_value("pdf_state", "")
    signer.easy_sign(dpg.get_value("pdf_input"))
    dpg.set_value("pdf_state", "Signed")

def _verify():
    dpg.set_value("pdf_state", "")
    verified = signer.easy_verify(dpg.get_value("pdf_input"))
    if verified:
        dpg.set_value("pdf_state", "Ok")
    else:
        dpg.set_value("pdf_state", "Invalid")
    print(verified)

def gui():
    dpg.create_context()
    dpg.create_viewport(title='PDF Signer', width=600, height=300)

    with dpg.window(label="Example Window", tag="Primary Window"):
        with dpg.group(tag="private_key"):
            dpg.add_text("Load private key")
            with dpg.file_dialog(directory_selector=False, file_count=1, tag="private_key_dialog", show=False, width=700 ,height=400, callback=lambda _1, x, _2: dpg.set_value("private_key_input", x["file_path_name"])):
                dpg.add_file_extension("Private keys (*.key){.key}", color=(0, 255, 255, 255))

            with dpg.group(horizontal=True):
                dpg.add_input_text(tag="private_key_input", readonly=True)
                dpg.add_button(label="Browse", callback=lambda: dpg.show_item("private_key_dialog"))
            dpg.add_input_text(tag="private_key_pass", label="Password")

            with dpg.group(horizontal=True):
                dpg.add_button(label="Load", tag="private_load", callback=_load_private_key)
                dpg.add_button(label="Clear", tag="private_clear", callback=_clear_private_key)
                dpg.add_text(tag="private_state")

        with dpg.group(tag="public_key"):
            dpg.add_text("Load public key")
            with dpg.file_dialog(directory_selector=False, file_count=1, tag="public_key_dialog", show=False, width=700 ,height=400, callback=lambda _1, x, _2: dpg.set_value("public_key_input", x["file_path_name"])):
                dpg.add_file_extension("Public keys (*.pub){.pub}", color=(0, 255, 255, 255))

            with dpg.group(horizontal=True):
                dpg.add_input_text(tag="public_key_input", readonly=True)
                dpg.add_button(label="Browse", callback=lambda: dpg.show_item("public_key_dialog"))

            with dpg.group(horizontal=True):
                dpg.add_button(label="Load", tag="public_load", callback=_load_public_key)
                dpg.add_button(label="Clear", tag="public_clear", callback=_clear_public_key)
                dpg.add_text(tag="public_state")
        
        with dpg.group(tag="document"):
            dpg.add_text("Select document")
            with dpg.file_dialog(directory_selector=False, file_count=1, tag="pdf_dialog", show=False, width=700 ,height=400, callback=lambda _1, x, _2: dpg.set_value("pdf_input", x["file_path_name"])):
                dpg.add_file_extension("PDF documents (*.pdf){.pdf}", color=(0, 255, 255, 255))

            with dpg.group(horizontal=True):
                dpg.add_input_text(tag="pdf_input", readonly=True)
                dpg.add_button(label="Browse", callback=lambda: dpg.show_item("pdf_dialog"))

            with dpg.group(horizontal=True):
                with dpg.group(tag="sign_grp"):
                    dpg.add_button(label="Sign", tag="sign", callback=_sign)
                dpg.add_button(label="Verify", tag="verify", callback=_verify)
                dpg.add_text("", tag="pdf_state")

        with dpg.group(tag="keygen"):
            dpg.add_text("Generate key")
            with dpg.group(horizontal=True):
                dpg.add_input_text(tag="keygen_input", default_value="a.key")
                dpg.add_button(label="Browse", callback=lambda: dpg.show_item("keygen_dialog"))
            dpg.add_input_text(tag="keygen_pass", label="Password")

            with dpg.group(horizontal=True):
                dpg.add_button(label="Generate", tag="keygen_generate", callback=_generate_keygen)

    dpg.disable_item("document")
    dpg.disable_item("sign_grp")

    dpg.setup_dearpygui()
    dpg.show_viewport()
    dpg.set_primary_window("Primary Window", True)
    dpg.start_dearpygui()
    dpg.destroy_context()
