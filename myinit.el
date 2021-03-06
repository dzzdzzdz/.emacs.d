(setq inhibit-startup-message t)
(tool-bar-mode -1)
(fset 'yes-or-no-p 'y-or-n-p)
(global-set-key (kbd "s-r") 'revert-buffer)
(column-number-mode 1)
(setq inhibit-startup-screen t)
(setq initial-scratch-message nil)
(global-linum-mode 1)
(global-visual-line-mode 1)

(global-subword-mode 1)
(set-face-attribute 'default nil :height 130)
(setq explicit-shell-file-name "/bin/zsh")

(defun my-backup-file-name (fpath)
  "Return a new file path of a given file path.
      If the new path's directories does not exist, create them."
  (let* (
	 (backupRootDir "~/.emacs.d/backup/")
	 (filePath (replace-regexp-in-string "[A-Za-z]:" "" fpath )) ; remove Windows driver letter in path, for example, “C:”
	 (backupFilePath (replace-regexp-in-string "//" "/" (concat backupRootDir filePath "~") ))
	 )
    (make-directory (file-name-directory backupFilePath) (file-name-directory backupFilePath))
    backupFilePath))

(setq make-backup-file-name-function 'my-backup-file-name)
;; use (C-c ') for editor

(add-hook 'eshell-mode-hook (lambda () (linum-mode -1)))

(use-package doom-themes
  :config
  ;; Global settings (defaults)
  (setq doom-themes-enable-bold t    ; if nil, bold is universally disabled
	doom-themes-enable-italic t) ; if nil, italics is universally disabled
  (load-theme 'doom-nova t)
  ;(load-theme 'doom-city-lights t)

  ;; Enable flashing mode-line on errors
  (doom-themes-visual-bell-config)

  ;; Enable custom neotree theme (all-the-icons must be installed!)
  (doom-themes-neotree-config)
  ;; or for treemacs users
  (setq doom-themes-treemacs-theme "doom-colors") ; use the colorful treemacs theme
  (doom-themes-treemacs-config)

  ;; Corrects (and improves) org-mode's native fontification.
  (doom-themes-org-config))

(global-set-key (kbd "M-o") 'other-window)
(global-set-key (kbd "C-<return>") 'execute-extended-command)
(global-set-key (kbd "C-x g") 'magit-status)
(global-set-key (kbd "C-x C-g") 'goto-line)

;(define-prefix-command 'z-map)
;(global-set-key (kbd "C-z") 'z-map)
;(define-key z-map (kbd "C-M-o") 'z/swap-windows)
(global-set-key (kbd "C-M-o") 'swap-windows)

;; (defun z/swap-windows ()
;;   ""
;;   (interactive)
;;   (ace-swap-window)
;;   (aw-flip-window)
;;   )
(defun swap-windows ()
  ""
  (interactive)
  (ace-swap-window)
  (aw-flip-window)
  )

(use-package try
  :ensure t)

(use-package quelpa
  :ensure t)

(use-package which-key
  :ensure t
  :config (which-key-mode))

(use-package org-bullets
  :ensure t
  :config
  (add-hook 'org-mode-hook (lambda () (org-bullets-mode 1))))
(use-package htmlize
  :ensure t)

(use-package org-drill
  :ensure t
  :init
  )

(setq ispell-program-name "/usr/local/bin/ispell")
(add-hook 'org-mode-hook 'flyspell-mode)
(add-hook 'text-mode-hook 'flyspell-mode)
(add-hook 'prog-mode-hook 'flyspell-prog-mode)
					; notes files
(setq org-agenda-files (list "~/.emacs.d/.notes/work/dh/main.org"
			     "~/.emacs.d/.notes/omscs/computerNetworking/i.org"
			     "~/.emacs.d/.notes/.dzzdzzdz.org"))

(setq indo-enable-flex-matching t)
(setq ido-everywhere t)
(ido-mode 1)

(defalias 'list-buffers 'ibuffer)
;; (defalias 'list-buffers 'ibuffer-other-window)

; If you like a tabbar
;; (use-package tabbar
;;   :ensure t
;;   :config
;;   (tabbar-mode 1))

(winner-mode 1) ; C-left, C-right for state
(windmove-default-keybindings) ; shift + arrow

(use-package ace-window
  :ensure t
  :config
  (progn
    (global-set-key [remap other-window] 'ace-window)

    (custom-set-faces
     '(aw-leading-char-face
       ((t (:inherit ace-jump-face-foreground :height 3.0)))))
    )
  (setq aw-scope 'visible))
  ;(setq aw-ignore-on t)
  ;(setq aw-ignored-buffers '("*minimap*"))

(use-package counsel
  :bind
  (("M-y" . counsel-yank-pop)
   :map ivy-minibuffer-map
   ("M-y" . ivy-next-line)))

(use-package swiper
  :ensure try
  :config
  (progn
    (ivy-mode 1)
    (setq ivy-use-virtual-buffers t)
    (global-set-key "\C-s" 'swiper)
    (global-set-key (kbd "C-c C-r") 'ivy-resume)
    (global-set-key (kbd "<f6>") 'ivy-resume)
    (global-set-key (kbd "M-x") 'counsel-M-x)
    (global-set-key (kbd "C-x C-f") 'counsel-find-file)
    (global-set-key (kbd "<f1> f") 'counsel-describe-function)
    (global-set-key (kbd "<f1> v") 'counsel-describe-variable)
    (global-set-key (kbd "<f1> l") 'counsel-load-library)
    (global-set-key (kbd "<f2> i") 'counsel-info-lookup-symbol)
    (global-set-key (kbd "<f2> u") 'counsel-unicode-char)
    (global-set-key (kbd "C-c g") 'counsel-git)
    (global-set-key (kbd "C-c j") 'counsel-git-grep)
    (global-set-key (kbd "C-c k") 'counsel-ag)
    (global-set-key (kbd "C-x l") 'counsel-locate)
    (global-set-key (kbd "C-S-o") 'counsel-rhythmbox)
    (define-key read-expression-map (kbd "C-r") 'counsel-expression-history)
    ))

(use-package auto-complete
  :ensure t
  :init
  (progn
    (ac-config-default)
    (global-auto-complete-mode t)
    ))

(use-package flycheck
  :ensure t
  :init
  (global-flycheck-mode t))

(use-package undo-tree
  :ensure t
  :init
  (global-undo-tree-mode))

(global-hl-line-mode t)

(use-package beacon
  :ensure t
  :config
  (beacon-mode 1)
  (setq beacon-color "#fcfc83"))

(use-package hungry-delete
  :ensure t
  :config
  (global-hungry-delete-mode))

(use-package aggressive-indent
  :ensure t
  :config)
  ;; (global-aggressive-indent-mode 0)
  ;; (add-hook 'emacs-lisp-mode-hook)
  ;; (add-hook 'css-mode-hook)
  ;; (add-to-list 'aggressive-indent-excluded-modes 'html-mode))

(use-package expand-region
  :ensure t
  :config
  (global-set-key (kbd "C-=") 'er/expand-region))

; C-;
(use-package iedit
  :ensure t)

(setq save-interprogram-paste-before-kill t)

(use-package magit
  :ensure t
  :config
  (global-set-key (kbd "C-<return>") 'magit-diff-visit-file-other-window))

(use-package diff-hl
  :ensure t
  :init
  (global-diff-hl-mode +1))

; TODO FIGURE OUT
;; (use-package forge
;;   :ensure t)

(use-package web-mode
  :ensure t
  :config
  (add-to-list 'auto-mode-alist '("\\.html?\\'" . web-mode))
  (setq web-mode-engines-alist
	'(("django" . "\\.html\\'")))
  (setq web-mode-ac-sources-alist
	'(("css" . (ac-source-css-property))
	  ("html" . (ac-source-words-in-buffer ac-source-abbrev))))

  (setq web-mode-enable-auto-closing t)
  (setq web-mode-enable-auto-quoting t))

(use-package json-mode
  :ensure t
  :init
  :config
  (setq-default indent-tabs-mode nil)
  (setq-default tab-width 2)
  (setq standard-indent 2))

(use-package minimap
  :ensure t
  :config
  (setq minimap-window-location "right"))

(use-package yaml-mode
  :ensure t
  :config
  (add-to-list 'auto-mode-alist '("\\.yml\\'" . yaml-mode))
  (add-to-list 'auto-mode-alist '("\\.yaml\\'" . yaml-mode))
  (add-hook 'yaml-mode-hook
	    '(lambda ()
	       (define-key yaml-mode-map "\C-m" 'newline-and-indent))))

(use-package projectile
  :ensure t
  :config
  (projectile-mode +1)
  (define-key projectile-mode-map (kbd "C-c C-p") 'projectile-command-map)
  (setq projectile-completion-system 'ivy))

;; (use-package counsel-projectile
;;   :ensure t
;;   :config
;;   (counsel-projectile-on))

(use-package dumb-jump
  :bind (("M-g o" . dumb-jump-go-other-window)
	 ("M-g j" . dumb-jump-go)
	 ("M-g x" . dumb-jump-go-prefer-external)
	 ("M-g z" . dumb-jump-go-prefer-external-other-window))
  :config 
  ;; (setq dumb-jump-selector 'ivy) ;; (setq dumb-jump-selector 'helm)
  :init
  (dumb-jump-mode)
  :ensure
  )

(global-set-key (kbd "C-x C-b") 'ibuffer)
(setq ibuffer-saved-filter-groups
      (quote (("default"
	       ("dired" (mode . dired-mode))
	       ("org" (name . "^.*org$"))

	       ("web" (or (mode . web-mode) (mode . js2-mode)))
	       ("shell" (or (mode . eshell-mode) (mode . shell-mode)))
	       ("mu4e" (name . "\*mu4e\*"))
	       ("programming" (or
			       (mode . python-mode)
			       (mode . c++-mode)))
	       ("emacs" (or
			 (name . "^\\*scratch\\*$")
			 (name . "^\\*Messages\\*$")))
	       ))))
(add-hook 'ibuffer-mode-hook
	  (lambda ()
	    (ibuffer-auto-mode 1)
	    (ibuffer-switch-to-saved-filter-groups "default")))

;; don't show these
					;(add-to-list 'ibuffer-never-show-predicates "zowie")
;; Don't show filter groups if there are no buffers in that group
(setq ibuffer-show-empty-filter-groups nil)

;; Don't ask for confirmation to delete marked buffers
(setq ibuffer-expert t)

(use-package emmet-mode
  :ensure t
  :config
  (add-hook 'sgml-mode-hook 'emmet-mode) ;; Auto-start on any markup modes
  (add-hook 'web-mode-hook 'emmet-mode) ;; Auto-start on any markup modes
  (add-hook 'css-mode-hook  'emmet-mode) ;; enable Emmet's css abbreviation.
  )

;; (use-package treemacs
;;     :ensure t
;;     :defer t
;;     :config
;;     (progn

;;       (setq treemacs-follow-after-init          t
;; 	    treemacs-width                      35
;; 	    treemacs-indentation                2
;; 	    treemacs-git-integration            t
;; 	    treemacs-collapse-dirs              3
;; 	    treemacs-silent-refresh             nil
;; 	    treemacs-change-root-without-asking nil
;; 	    treemacs-sorting                    'alphabetic-desc
;; 	    treemacs-show-hidden-files          t
;; 	    treemacs-never-persist              nil
;; 	    treemacs-is-never-other-window      nil
;; 	    treemacs-goto-tag-strategy          'refetch-index)

;;       (treemacs-follow-mode t)
;;       (treemacs-filewatch-mode t))
;;     :bind
;;     (:map global-map
;; 	  ([f8]        . treemacs-toggle)
;; 	  ([f9]        . treemacs-projectile-toggle)
;; 	  ("<C-M-tab>" . treemacs-toggle)
;; 	  ("M-0"       . treemacs-select-window)
;; 	  ("C-c 1"     . treemacs-delete-other-windows)
;; 	))
;;   (use-package treemacs-projectile
;;     :defer t
;;     :ensure t
;;     :config
;;     (setq treemacs-header-function #'treemacs-projectile-create-header)
;; )

(quelpa '(dired+ :fetcher github :repo "emacsmirror/dired-plus"))
(use-package dired+
  :ensure t
  :config (require 'dired+))

(setq dired-dwim-target t)

(use-package dired-narrow
  :ensure t
  :config
  (bind-key "C-c C-n" #'dired-narrow)
  (bind-key "C-c C-f" #'dired-narrow-fuzzy)
  (bind-key "C-x C-N" #'dired-narrow-regexp)
  )

(use-package dired-subtree
  :ensure t
  :after dired
  :config
  (bind-key "<tab>" #'dired-subtree-toggle dired-mode-map)
  (bind-key "<backtab>" #'dired-subtree-cycle dired-mode-map))

(use-package wgrep
  :ensure t
  )

(use-package pcre2el
  :ensure t
  :config
  (pcre-mode)
  )

(use-package all-the-icons 
:ensure t
:defer 0.5)

(use-package all-the-icons-dired
:ensure t
)

(add-hook 'dired-mode-hook 'all-the-icons-dired-mode)

(use-package pdf-tools
  :ensure t)
(require 'pdf-tools)

(use-package eyebrowse
  :ensure t
  :config
  (eyebrowse-mode))

(use-package dictionary
  :ensure t)

( use-package synosaurus
  :ensure t)

(use-package restclient
  :ensure t)
(use-package company-restclient
  :ensure t
  :config
  (add-to-list 'company-backends 'company-restclient))

;; (use-package live-py-mode
;;   :ensure t)

(use-package keypression
  :ensure t
  :config
  (setq keypression-fade-out-delay 0.3))
