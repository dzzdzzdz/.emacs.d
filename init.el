(require 'package)
(setq package-enable-at-startup nil)
(add-to-list 'package-archives
	     '("melpa" . "https://melpa.org/packages/"))
(add-to-list 'package-archives
	     '("gnu" . "https://elpa.gnu.org/packages/"))

(package-initialize)

;; Bootstrap `use-package'
(unless (package-installed-p 'use-package)
  (package-refresh-contents)
  (package-install 'use-package))

(org-babel-load-file (expand-file-name "~/.emacs.d/myinit.org"))

(custom-set-variables
 ;; custom-set-variables was added by Custom.
 ;; If you edit it by hand, you could mess it up, so be careful.
 ;; Your init file should contain only one such instance.
 ;; If there is more than one, they won't work right.
 '(package-selected-packages
   '(dotenv-mode org-drill keypression live-py-mode forge foreg company-restclient restclient dired-subtree dired-narrow synosaurus dictionary pdf-tools git-timemachine git-gutter quelpa wgrep pcre2el dired+ all-the-icons-dired all-the-icons treemacs-persp treemacs-magit treemacs-icons-dired treemacs-projectile treemacs-evil treemacs emmet-mode dumb-jump counsel-projectile projectile yml-mode yaml-mode f minimap json-mode web-mode doom-themes magit iedit expand-region aggressive-indent hungry-delete beacon undo-tree htmlize which-key try use-package tabbar orgalist org-bullets counsel color-theme-modern color-theme auto-complete ace-window)))
(custom-set-faces
 ;; custom-set-faces was added by Custom.
 ;; If you edit it by hand, you could mess it up, so be careful.
 ;; Your init file should contain only one such instance.
 ;; If there is more than one, they won't work right.
 '(aw-leading-char-face ((t (:inherit ace-jump-face-foreground :height 3.0)))))
(put 'dired-find-alternate-file 'disabled nil)
