package templates

import (
	g "github.com/maragudk/gomponents"
	. "github.com/maragudk/gomponents/html"
)

type LayoutProps struct {
	Title       string
	CurrentUser string
}

func NavbarComponent(props LayoutProps) g.Node {
	return Nav(Class("nav"),
		Div(Class("nav-left"),
			Div(Class("brand"), A(Href("/"), g.Text("Guestbooks"))),
		),
		Div(Class("nav-links nav-right"),
			g.If(props.CurrentUser == "",
				Div(
					A(Href("/login"), g.Text("Login")),
					A(Href("/register"), g.Text("Register")),
				),
			),
			g.If(props.CurrentUser != "",
				Div(Class("row"),
					Div(Class("col"), g.Textf("Logged in as %s", props.CurrentUser)),
					Div(Class("col"), A(Href("/logout"), g.Text("Logout"))),
				)),
		),
	)
}

func FooterComponent() g.Node {
	return Footer(Class("footer"),
		g.Raw(`
			<div class="open-source-notice">
				<small><i>This project is <a href="https://codeberg.org/meadowingc/guestbooks">open
							source</a>! Any contributions are welcome.</i></small>
			</div>
			<p class="with-love">
				<small>Made with ❤️ by <a target="_blank" href="https://meadow.cafe/">Meadow</a></small>
			</p>
		`),
	)
}

func CookieBannerComponent() g.Node {
	return g.Raw(`
		<div id="cookie-banner"
			style="display: none; position: fixed; bottom: 0; left:0; width: 100%; background-color: #f9ed69; padding: 20px 0; text-align: center;">
			<p style="margin: 0; padding: 0; color: black;">
				This website uses cookies for basic functionality (track your session so the platform knows who you are).
				<br />
				If you continue to use this site, you agree to the use of cookies, otherwise you should leave the site.
			</p>

			<div style="margin-top: 10px;">
				<button id="accept-cookies" style="margin-right: 15px; padding: 10px;">Accept</button>
				<button onclick="rejectCookies();" style="padding: 10px;">I don't want your cookies!</button>
			</div>

		</div>
		<script>
			(function () {
				var acceptedCookies = localStorage.getItem('acceptedCookies');
				if (!acceptedCookies) {
					document.getElementById('cookie-banner').style.display = 'block';
				}

				document.getElementById('accept-cookies').onclick = function () {
					localStorage.setItem('acceptedCookies', 'true');
					document.getElementById('cookie-banner').style.display = 'none';
				}
			})()

			function rejectCookies() {
				document.body.innerHTML = '<h1 style="text-align: center; margin-top: 20%;">We\'re sad to see you go, but we respect your cookie choices. Have a cookie-free day!</h1>';
			}
		</script>
	`)
}

func Layout(props LayoutProps, children ...g.Node) g.Node {
	return Doctype(
		HTML(
			Lang("en"),
			Head(
				Meta(Charset("utf-8")),
				Meta(Name("viewport"), Content("width=device-width, initial-scale=1")),
				Link(Rel("icon"), Type("image/png"), Href("data:image/svg+xml,<svg xmlns=%22http://www.w3.org/2000/svg%22 viewBox=%220 0 100 100%22><text y=%22.9em%22 font-size=%2290%22>😺</text></svg>")),

				Link(Rel("stylesheet"), Href("/assets/css/chota.min.css")),
				Link(Rel("stylesheet"), Href("/assets/css/main.css")),

				TitleEl(g.Text(props.Title)),
			),
			Body(
				Div(Class("container"), Style("margin-top: 1.5em;"),
					NavbarComponent(props),
					Main(
						g.Group(children),
					),
				),
				FooterComponent(),
				CookieBannerComponent(),
			),
		),
	)
}
