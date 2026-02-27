import { sveltekit } from '@sveltejs/kit/vite'
import { defineConfig } from 'vite'

export default defineConfig({
	plugins: [sveltekit()],
	server: {
		proxy: {
			'/api/devices': {
				target: 'http://localhost:8081',
				rewrite: (path) => path.replace('/api/devices', '/devices'),
			},
			'/api/alerts': {
				target: 'http://localhost:8080',
				rewrite: (path) => path.replace('/api/alerts', '/alerts'),
			},
		},
	},
})
