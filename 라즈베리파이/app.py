import os
import re
from flask import Flask, Response, request, render_template_string, redirect, url_for, session

app = Flask(__name__)
# 세션(로그인 상태 저장) 암호화를 위한 고유 키 설정
app.secret_key = "smu_center_project_secret_key_!!!"

# =================================================================
# [실험 세팅용 환경 변수 설정 영역]
# =================================================================
# 1. 실제 사용 중인 IP 카메라의 정확한 RTSP 주소 입력
RTSP_URL = "rtsp://계정이름:비밀번호@아이피:포트/stream1 or stream2" # 1 = 고화질, 2 = 저화질

# 2. 시스템 관제용 기본 계정 정보 설정
WEB_USER_ID = "admin"
WEB_USER_PW = "admin1234"

# 3. 관리자(인증 성공) 기기로 등록할 하드웨어의 물리 MAC 주소 화이트리스트
ADMIN_MAC_WHITELIST = [
]
# =================================================================

# 영상 처리 모듈 초기화 (지연 로딩 방지를 위해 전역 선언)
from masking_engine import MaskingEngine
masking_engine = MaskingEngine(model_path="pose_landmarker_lite.task", rtsp_url=RTSP_URL)

def get_client_mac(client_ip):
    """라즈베리파이 내부 ARP 테이블을 파싱하여 접속자 IP에 매핑된 진짜 MAC 주소 추출"""
    if client_ip == "127.0.0.1":
        return "localhost"
    try:
        with os.popen(f"arp -n {client_ip}") as f:
            arp_output = f.read()
        mac_match = re.search(r"([0-9a-fA-F]{2}[:-]){5}([0-9a-fA-F]{2})", arp_output)
        if mac_match:
            return mac_match.group(0).lower().replace("-", ":")
    except Exception as e:
        print(f"[오류] MAC 주소 파싱 실패: {e}")
    return None

# -----------------------------------------------------------------
# [Web 인터페이스 라우팅 영역]
# -----------------------------------------------------------------

@app.route('/login', methods=['GET', 'POST'])
def login():
    """사용자 인증을 위한 로그인 페이지"""
    error = None
    if request.method == 'POST':
        # 사용자가 입력한 ID / PW 가져오기
        user_id = request.form.get('username')
        user_pw = request.form.get('password')
        
        # 계정 검증 수행
        if user_id == WEB_USER_ID and user_pw == WEB_USER_PW:
            session['logged_in'] = True  # 세션에 로그인 성공 저장
            return redirect(url_for('index'))
        else:
            error = "계정 정보가 일치하지 않습니다. 다시 입력해주세요."

    # 별도의 파일 없이 깔끔하게 렌더링하기 위한 인라인 로그인 HTML
    login_html = """
    <html>
        <head>
            <title>CCTV Gateway Login</title>
            <style>
                body { font-family: Arial, sans-serif; background: #121212; color: #fff; display: flex; justify-content: center; align-items: center; height: 100vh; margin: 0; }
                .login-box { background: #1e1e1e; padding: 40px; border-radius: 10px; box-shadow: 0 4px 15px rgba(0,0,0,0.5); width: 320px; text-align: center; }
                h2 { color: #00adb5; margin-bottom: 25px; }
                input[type="text"], input[type="password"] { width: 100%; padding: 10px; margin-bottom: 15px; border: 1px solid #333; border-radius: 5px; background: #2d2d2d; color: #fff; box-sizing: border-box; }
                button { width: 100%; padding: 12px; background: #00adb5; border: none; border-radius: 5px; color: #fff; font-size: 16px; cursor: pointer; font-weight: bold; }
                button:hover { background: #008c95; }
                .error { color: #f44336; font-size: 14px; margin-bottom: 15px; text-align: left; }
            </style>
        </head>
        <body>
            <div class="login-box">
                <h2>IoT 보안 게이트웨이</h2>
                {% if error %}<div class="error">{{ error }}</div>{% endif %}
                <form method="POST">
                    <input type="text" name="username" placeholder="아이디 입력" required>
                    <input type="password" name="password" placeholder="비밀번호 입력" required>
                    <button type="submit">시스템 관제 로그인</button>
                </form>
            </div>
        </body>
    </html>
    """
    return render_template_string(login_html, error=error)


@app.route('/')
def index():
    """메인 영상 관제 웹 대시보드 (로그인 세션 체크 필수)"""
    # 로그인 세션이 없다면 로그인 페이지로 강제 튕구기
    if not session.get('logged_in'):
        return redirect(url_for('login'))

    client_ip = request.remote_addr
    client_mac = get_client_mac(client_ip)
    
    # 1단계 로그인(지식 기반) 통과 후, 2단계 기기 식별(소유 기반) 상태 진단
    is_admin_device = client_mac in ADMIN_MAC_WHITELIST or client_ip == "127.0.0.1"

    html_layout = f"""
    <html>
        <head>
            <title>Zero-Trust Security Gateway Dashboard</title>
            <style>
                body {{ font-family: Arial, sans-serif; background: #121212; color: #fff; text-align: center; padding-top: 30px; }}
                .container {{ display: inline-block; background: #1e1e1e; padding: 20px; border-radius: 10px; box-shadow: 0 4px 15px rgba(0,0,0,0.5); }}
                h2 {{ color: #00adb5; }}
                .info-box {{ background: #2d2d2d; padding: 10px; margin-bottom: 20px; border-radius: 5px; font-size: 14px; text-align: left; line-height: 1.6; }}
                .status-admin {{ color: #4caf50; font-weight: bold; }}
                .status-guest {{ color: #f44336; font-weight: bold; }}
                .btn-logout {{ display: inline-block; padding: 5px 10px; background: #333; color: #fff; text-decoration: none; border-radius: 4px; float: right; font-size: 12px; }}
                .btn-logout:hover {{ background: #444; }}
                img {{ border: 3px solid #333; border-radius: 5px; max-width: 100%; }}
            </style>
        </head>
        <body>
            <div class="container">
                <a href="/logout" class="btn-logout">로그아웃</a>
                <h2>[선문대 기업연계 프로젝트] IoT 보안 게이트웨이 관제망</h2>
                <div class="info-box">
                    • <b>접속 클라이언트 IP:</b> {client_ip}<br>
                    • <b>보안 식별자 (MAC 주소):</b> {client_mac if client_mac else "조회 불가(외부망)"}<br>
                    • <b>시스템 보안 인증 단계:</b> <span class="status-admin">1차 사용자 계정 인증 통과 (Success)</span><br>
                    • <b>디바이스 보안 제어 모드:</b> {"<span class='status-admin'>FULL ACCESS (ADMIN ORIGIN)</span>" if is_admin_device else "<span class='status-guest'>SECURITY MASKING (GUEST FILTER)</span>"}
                </div>
                <div>
                    <img src="/video_feed" width="640" height="480">
                </div>
            </div>
        </body>
    </html>
    """
    return render_template_string(html_layout)


@app.route('/logout')
def logout():
    """로그아웃 처리 후 로그인 페이지로 리다이렉트"""
    session.clear()
    return redirect(url_for('login'))


@app.route('/video_feed')
def video_feed():
    """접속자의 물리 MAC 주소 화이트리스트 검증 기반 동적 분기 실시간 스트리밍 루프"""
    # 비정상적인 방법으로 스트리밍 API에 직접 접근할 경우 세션 차단 (보안 강화)
    if not session.get('logged_in'):
        return "Access Denied", 401

    client_ip = request.remote_addr
    client_mac = get_client_mac(client_ip)
    
    print(f"\n=========================================================")
    print(f"▶ [실시간 접근 탐지] IP: {client_ip} | 하드웨어 MAC: {client_mac}")

    # 제로 트러스트 기기 매핑 분기 제어
    if client_mac in ADMIN_MAC_WHITELIST or client_ip == "127.0.0.1":
        current_mode = "admin"
        print(" [인증 완료] 화이트리스트 등록 기기 확인 -> 원본 영상 스트리밍 승인")
    else:
        current_mode = "guest"
        print(" [⚠️ 경고] 미등록 무단 접근 기기 기각 -> 프라이버시 보호 마스킹 자동 강제 인입")
    print(f"=========================================================")

    return Response(masking_engine.generate_frames(current_mode),
                    mimetype='multipart/x-mixed-replace; boundary=frame')


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=False)
