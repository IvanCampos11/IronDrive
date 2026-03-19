.PHONY: build-css watch-css dev

build-css:
	./tailwindcss -i static/css/input.css -o static/css/style.css --minify

watch-css:
	./tailwindcss -i static/css/input.css -o static/css/style.css --watch

dev:
	$(MAKE) watch-css &
	cargo run
