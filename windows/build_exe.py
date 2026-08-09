import os
import sys
import subprocess

PROJECT_ROOT = os.path.dirname(os.path.dirname(__file__))
ICON_SRC = os.path.join(PROJECT_ROOT, "windows", "resources", "icon.ico")


def ensure_icon():
    if os.path.exists(ICON_SRC):
        return ICON_SRC
    try:
        from PIL import Image, ImageDraw
        img = Image.new('RGBA', (64, 64), (0, 0, 0, 0))
        draw = ImageDraw.Draw(img)
        draw.ellipse([2, 2, 62, 62], fill='#1976D2')
        draw.ellipse([10, 10, 54, 54], fill='#1565C0')
        draw.text((12, 16), "DNS", fill='white')
        os.makedirs(os.path.dirname(ICON_SRC), exist_ok=True)
        img.save(ICON_SRC, format="ICO", sizes=[(64, 64)])
        return ICON_SRC
    except Exception:
        return None


def main():
    print("正在安装 PyInstaller...")
    subprocess.check_call([sys.executable, "-m", "pip", "install", "pyinstaller"])

    icon_path = ensure_icon()
    main_script = os.path.join(PROJECT_ROOT, "windows", "main.py")
    core_script = os.path.join(PROJECT_ROOT, "dns-txt-proxy.py")
    config_file = os.path.join(PROJECT_ROOT, "config.conf.example")

    cmd = [
        sys.executable, "-m", "PyInstaller",
        main_script,
        "--onefile",
        "--windowed",
        "--name=DNS-TXT-Proxy-Manager",
        "--add-data", f"{core_script}{os.pathsep}.",
        "--add-data", f"{config_file}{os.pathsep}config.conf",
        "--hidden-import", "dns.resolver",
        "--distpath", os.path.join(PROJECT_ROOT, "dist"),
        "--workpath", os.path.join(PROJECT_ROOT, "build"),
        "--specpath", PROJECT_ROOT,
        "--clean",
        "--noconfirm",
    ]
    if icon_path:
        cmd.insert(4, f"--icon={icon_path}")

    print("正在打包成单 exe...")
    subprocess.check_call(cmd)
    exe_path = os.path.join(PROJECT_ROOT, "dist", "DNS-TXT-Proxy-Manager.exe")
    print(f"\n打包完成：{exe_path}")
    print(f"大小：{os.path.getsize(exe_path) / 1024 / 1024:.1f} MB")


if __name__ == "__main__":
    main()
