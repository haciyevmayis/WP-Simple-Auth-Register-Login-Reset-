<?php
/**
 * Plugin Name: WP Simple Auth (Register/Login/Reset)
 * Description: Kısa kodlarla üye kaydı, giriş ve parola sıfırlama. [wp_auth_register], [wp_auth_login], [wp_auth_reset]
 * Version: 1.0.0
 * Author: you
 * License: GPL2+
 */

if ( ! defined( 'ABSPATH' ) ) exit;

final class WP_Simple_Auth {
	public function __construct() {
		add_shortcode( 'wp_auth_register', [ $this, 'shortcode_register' ] );
		add_shortcode( 'wp_auth_login',    [ $this, 'shortcode_login' ] );
		add_shortcode( 'wp_auth_reset',    [ $this, 'shortcode_reset' ] );

		add_action( 'init', [ $this, 'maybe_handle_post' ] );

		// Varsayılan redirect
		add_filter( 'login_redirect', [ $this, 'default_login_redirect' ], 10, 3 );
		// Basit stiller
		add_action( 'wp_head', [ $this, 'inline_styles' ] );
	}

	/* =======================
	 *  Helpers
	 * ======================= */

	private function field( $name, $default = '' ) {
		return isset( $_POST[$name] ) ? wp_unslash( $_POST[$name] ) : $default;
	}

	private function msg( $type, $text ) {
		$type = $type === 'error' ? 'error' : 'success';
		return '<div class="wpa-notice wpa-' . esc_attr($type) . '">' . esc_html($text) . '</div>';
	}

	private function nonce_field( $action ) {
		return wp_nonce_field( 'wpa_' . $action, 'wpa_nonce', true, false );
	}

	private function verify_nonce( $action ) {
		return isset($_POST['wpa_nonce']) && wp_verify_nonce( sanitize_text_field( wp_unslash( $_POST['wpa_nonce'] ) ), 'wpa_' . $action );
	}

	private function is_username_email_unique( $username, $email, &$error ) {
		if ( username_exists( $username ) ) { $error = __( 'Kullanıcı adı zaten kullanılıyor.', 'wp-simple-auth' ); return false; }
		if ( email_exists( $email ) )       { $error = __( 'E-posta zaten kayıtlı.', 'wp-simple-auth' ); return false; }
		return true;
	}

	/* =======================
	 *  POST handlers
	 * ======================= */

	public function maybe_handle_post() {
		if ( ! isset($_POST['wpa_action']) ) return;

		switch ( sanitize_text_field( wp_unslash( $_POST['wpa_action'] ) ) ) {
			case 'register':
				$this->handle_register();
				break;
			case 'login':
				$this->handle_login();
				break;
			case 'reset':
				$this->handle_reset();
				break;
		}
	}

	private function handle_register() {
		if ( ! $this->verify_nonce('register') ) return;

		$username = sanitize_user( $this->field('username') );
		$email    = sanitize_email( $this->field('email') );
		$pass1    = $this->field('password');
		$pass2    = $this->field('password_confirm');

		$errors = new WP_Error();

		if ( empty($username) || empty($email) || empty($pass1) || empty($pass2) ) {
			$errors->add('empty', __( 'Tüm alanlar zorunludur.', 'wp-simple-auth' ));
		}
		if ( $pass1 !== $pass2 ) {
			$errors->add('mismatch', __( 'Parolalar eşleşmiyor.', 'wp-simple-auth' ));
		}
		if ( ! is_email( $email ) ) {
			$errors->add('email', __( 'Geçerli bir e-posta girin.', 'wp-simple-auth' ));
		}

		$unique_err = '';
		if ( ! $this->is_username_email_unique( $username, $email, $unique_err ) ) {
			$errors->add('unique', $unique_err);
		}

		if ( $errors->has_errors() ) {
			set_transient( 'wpa_register_errors_' . $this->nonce_key(), $errors, 60 );
			return;
		}

		$user_id = wp_create_user( $username, $pass1, $email );
		if ( is_wp_error( $user_id ) ) {
			$errors->add('create', $user_id->get_error_message());
			set_transient( 'wpa_register_errors_' . $this->nonce_key(), $errors, 60 );
			return;
		}

		// İsteğe göre otomatik giriş
		wp_signon( [
			'user_login'    => $username,
			'user_password' => $pass1,
			'remember'      => true
		], is_ssl() );

		wp_safe_redirect( $this->get_redirect_url() );
		exit;
	}

	private function handle_login() {
		if ( ! $this->verify_nonce('login') ) return;

		$login    = sanitize_text_field( $this->field('login') );
		$password = $this->field('password');
		$remember = isset($_POST['remember']);

		// E-posta ile giriş destekle
		if ( is_email( $login ) ) {
			$user = get_user_by( 'email', $login );
			if ( $user ) { $login = $user->user_login; }
		}

		$user = wp_signon( [
			'user_login'    => $login,
			'user_password' => $password,
			'remember'      => $remember
		], is_ssl() );

		if ( is_wp_error( $user ) ) {
			$err = new WP_Error();
			$err->add('login', $user->get_error_message());
			set_transient( 'wpa_login_errors_' . $this->nonce_key(), $err, 60 );
			return;
		}

		wp_safe_redirect( $this->get_redirect_url() );
		exit;
	}

	private function handle_reset() {
		if ( ! $this->verify_nonce('reset') ) return;

		$login = sanitize_text_field( $this->field('login') );

		if ( empty( $login ) ) {
			$err = new WP_Error();
			$err->add('empty', __( 'Kullanıcı adı veya e-posta girin.', 'wp-simple-auth' ));
			set_transient( 'wpa_reset_errors_' . $this->nonce_key(), $err, 60 );
			return;
		}

		// WP’nin yerleşik şifre sıfırlamasını tetikle
		$user = is_email( $login ) ? get_user_by( 'email', $login ) : get_user_by( 'login', $login );
		if ( ! $user ) {
			$err = new WP_Error();
			$err->add('notfound', __( 'Kullanıcı bulunamadı.', 'wp-simple-auth' ));
			set_transient( 'wpa_reset_errors_' . $this->nonce_key(), $err, 60 );
			return;
		}

		$result = retrieve_password( $user->user_login );
		if ( is_wp_error( $result ) ) {
			$err = new WP_Error();
			$err->add('mail', $result->get_error_message());
			set_transient( 'wpa_reset_errors_' . $this->nonce_key(), $err, 60 );
			return;
		}

		set_transient( 'wpa_reset_success_' . $this->nonce_key(), __( 'Sıfırlama e-postası gönderildi. Lütfen gelen kutunuzu kontrol edin.', 'wp-simple-auth' ), 60 );
	}

	private function get_redirect_url() {
		$redirect = isset($_POST['redirect_to']) ? esc_url_raw( wp_unslash( $_POST['redirect_to'] ) ) : home_url('/');
		// Güvenlik: yalnız site içi
		if ( $redirect && 0 === strpos( $redirect, home_url() ) ) {
			return $redirect;
		}
		return home_url('/');
	}

	private function nonce_key() {
		// Aynı sayfada tekrar yüklemede mesajları çekmek için basit anahtar
		return wp_hash( (string) ( get_current_user_id() ?: 0 ) . '|' . ( isset($_POST['_wp_http_referer']) ? sanitize_text_field( wp_unslash( $_POST['_wp_http_referer'] ) ) : '' ) );
	}

	public function default_login_redirect( $redirect_to, $request, $user ) {
		// İstersen özelleştir: Rol bazlı yönlendirme
		if ( is_wp_error( $user ) || ! $user ) return $redirect_to;
		return $redirect_to ?: home_url('/my-account/');
	}

	/* =======================
	 *  Shortcodes (Forms)
	 * ======================= */

	public function shortcode_register( $atts = [] ) {
		if ( is_user_logged_in() ) return $this->msg('success', __( 'Zaten giriş yaptınız.', 'wp-simple-auth' ));
		$errors = get_transient( 'wpa_register_errors_' . $this->nonce_key() );

		ob_start(); ?>
		<form class="wpa-form" method="post">
			<h3><?php esc_html_e('Kayıt Ol', 'wp-simple-auth'); ?></h3>
			<?php
				if ( $errors instanceof WP_Error ) {
					foreach ( $errors->get_error_messages() as $m ) echo $this->msg('error', $m);
					delete_transient( 'wpa_register_errors_' . $this->nonce_key() );
				}
			?>
			<label>
				<span><?php esc_html_e('Kullanıcı Adı', 'wp-simple-auth'); ?></span>
				<input type="text" name="username" value="<?php echo esc_attr( $this->field('username') ); ?>" required>
			</label>
			<label>
				<span><?php esc_html_e('E-posta', 'wp-simple-auth'); ?></span>
				<input type="email" name="email" value="<?php echo esc_attr( $this->field('email') ); ?>" required>
			</label>
			<label>
				<span><?php esc_html_e('Parola', 'wp-simple-auth'); ?></span>
				<input type="password" name="password" required>
			</label>
			<label>
				<span><?php esc_html_e('Parola (Tekrar)', 'wp-simple-auth'); ?></span>
				<input type="password" name="password_confirm" required>
			</label>

			<input type="hidden" name="wpa_action" value="register">
			<?php echo $this->nonce_field('register'); ?>
			<input type="hidden" name="redirect_to" value="<?php echo esc_url( (string) ( $_GET['redirect_to'] ?? '' ) ); ?>">
			<?php wp_referer_field(); ?>
			<button type="submit"><?php esc_html_e('Hesap Oluştur', 'wp-simple-auth'); ?></button>
		</form>
		<?php
		return ob_get_clean();
	}

	public function shortcode_login( $atts = [] ) {
		if ( is_user_logged_in() ) return $this->msg('success', __( 'Zaten giriş yaptınız.', 'wp-simple-auth' ));
		$errors = get_transient( 'wpa_login_errors_' . $this->nonce_key() );

		ob_start(); ?>
		<form class="wpa-form" method="post">
			<h3><?php esc_html_e('Giriş Yap', 'wp-simple-auth'); ?></h3>
			<?php
				if ( $errors instanceof WP_Error ) {
					foreach ( $errors->get_error_messages() as $m ) echo $this->msg('error', $m);
					delete_transient( 'wpa_login_errors_' . $this->nonce_key() );
				}
			?>
			<label>
				<span><?php esc_html_e('Kullanıcı Adı veya E-posta', 'wp-simple-auth'); ?></span>
				<input type="text" name="login" value="<?php echo esc_attr( $this->field('login') ); ?>" required>
			</label>
			<label>
				<span><?php esc_html_e('Parola', 'wp-simple-auth'); ?></span>
				<input type="password" name="password" required>
			</label>
			<label class="wpa-remember">
				<input type="checkbox" name="remember" value="1"> <span><?php esc_html_e('Beni hatırla', 'wp-simple-auth'); ?></span>
			</label>

			<input type="hidden" name="wpa_action" value="login">
			<?php echo $this->nonce_field('login'); ?>
			<input type="hidden" name="redirect_to" value="<?php echo esc_url( (string) ( $_GET['redirect_to'] ?? '' ) ); ?>">
			<?php wp_referer_field(); ?>
			<button type="submit"><?php esc_html_e('Giriş', 'wp-simple-auth'); ?></button>

			<p class="wpa-links">
				<a href="<?php echo esc_url( add_query_arg( 'show', 'reset', get_permalink() ?: home_url( add_query_arg( NULL, NULL ) ) ) ); ?>"><?php esc_html_e('Parolanı mı unuttun?', 'wp-simple-auth'); ?></a>
			</p>
		</form>
		<?php
		return ob_get_clean();
	}

	public function shortcode_reset( $atts = [] ) {
		$errors  = get_transient( 'wpa_reset_errors_' . $this->nonce_key() );
		$success = get_transient( 'wpa_reset_success_' . $this->nonce_key() );

		ob_start(); ?>
		<form class="wpa-form" method="post">
			<h3><?php esc_html_e('Parola Sıfırlama', 'wp-simple-auth'); ?></h3>
			<?php
				if ( $success ) {
					echo $this->msg('success', $success);
					delete_transient( 'wpa_reset_success_' . $this->nonce_key() );
				}
				if ( $errors instanceof WP_Error ) {
					foreach ( $errors->get_error_messages() as $m ) echo $this->msg('error', $m);
					delete_transient( 'wpa_reset_errors_' . $this->nonce_key() );
				}
			?>
			<label>
				<span><?php esc_html_e('Kullanıcı Adı veya E-posta', 'wp-simple-auth'); ?></span>
				<input type="text" name="login" value="<?php echo esc_attr( $this->field('login') ); ?>" required>
			</label>

			<input type="hidden" name="wpa_action" value="reset">
			<?php echo $this->nonce_field('reset'); ?>
			<?php wp_referer_field(); ?>
			<button type="submit"><?php esc_html_e('Sıfırlama Bağlantısı Gönder', 'wp-simple-auth'); ?></button>
		</form>
		<?php
		return ob_get_clean();
	}

	/* =======================
	 *  Styles
	 * ======================= */
	public function inline_styles() {
		?>
		<style id="wp-simple-auth-styles">
			.wpa-form{max-width:520px;margin:24px auto;padding:20px;border:1px solid #e5e7eb;border-radius:16px;background:#fff}
			.wpa-form h3{margin:0 0 12px;font-size:22px}
			.wpa-form label{display:block;margin:10px 0}
			.wpa-form label span{display:block;margin-bottom:6px;font-weight:600}
			.wpa-form input[type="text"],
			.wpa-form input[type="email"],
			.wpa-form input[type="password"]{width:100%;padding:10px;border:1px solid #d1d5db;border-radius:10px}
			.wpa-form button{width:100%;padding:10px 14px;border:0;border-radius:12px;background:#111;color:#fff;font-weight:600;cursor:pointer}
			.wpa-form button:hover{opacity:.95}
			.wpa-remember{display:flex;align-items:center;gap:8px}
			.wpa-links{margin-top:10px;text-align:center}
			.wpa-notice{margin:8px 0;padding:10px;border-radius:10px;font-size:14px}
			.wpa-success{background:#ecfdf5;border:1px solid #10b981;color:#065f46}
			.wpa-error{background:#fef2f2;border:1px solid #ef4444;color:#7f1d1d}
		</style>
		<?php
	}
}

new WP_Simple_Auth();
