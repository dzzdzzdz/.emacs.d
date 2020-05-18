(setq inhibit-startup-message t)
(tool-bar-mode -1)
(fset 'yes-or-no-p 'y-or-n-p)
(global-set-key (kbd "<f5>") 'revert-buffer)
(column-number-mode 1)
(setq inhibit-startup-screen t)
(setq initial-scratch-message nil)
(global-linum-mode 1)
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

(use-package doom-themes
  :config
  ;; Global settings (defaults)
  (setq doom-themes-enable-bold t    ; if nil, bold is universally disabled
	doom-themes-enable-italic t) ; if nil, italics is universally disabled
  (load-theme 'doom-nova t)

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
;(global-set-key (kbd "C-x g") 'magit-status)
(global-set-key (kbd "M-o") 'ace-window)
(global-set-key (kbd "C-x C-g") 'goto-line)

(use-package try
  :ensure t)

(use-package which-key
  :ensure t
  :config (which-key-mode))

(use-package org-bullets
  :ensure t
  :config
  (add-hook 'org-mode-hook (lambda () (org-bullets-mode 1))))

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

(use-package ace-window
  :ensure t
  :init
  (progn
    (global-set-key [remap other-window] 'ace-window)
    (custom-set-faces
     '(aw-leading-char-face
       ((t (:inherit ace-jump-face-foreground :height 3.0)))))
    ))

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
  (setq beacon-color "#666600"))

(use-package hungry-delete
  :ensure t
  :config
  (global-hungry-delete-mode))

(use-package aggressive-indent
  :ensure t
  :config
  (global-aggressive-indent-mode 1))

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
  :init)
