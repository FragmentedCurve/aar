;;;
;;; To use this elisp script, add the following target to your
;;; Makefile,
;;;
;;;     README README.md: README.org
;;;	    emacs -Q --batch --script readme.el
;;;
;;;
;;; 

(with-temp-buffer
  ;; Initialize org mode
  (org-mode)
  (add-to-list 'org-export-backends 'md)

  ;; Export plain text README.
  (insert-file-contents "README.org")
  (org-export-to-file 'ascii "README")

  ;; Export a markdown README.
  ;;
  ;; This README.md uses a custom backend that uses
  ;; #+TITLE as a level 1 header. All other headers
  ;; are level 2 or greater.
  (org-export-to-file (org-export-create-backend
                       :parent 'md
                       :transcoders `((headline . ,(lambda (obj content info)
                                                     (format "%s %s\n\n%s"
                                                             (make-string
                                                              (+ 1 (org-export-get-relative-level obj info))
                                                              (string-to-char "#"))
                                                             (org-export-data (org-element-property :title obj) info)
                                                             (if content content ""))))
                                      (template . ,(lambda (content info)
                                                     (let ((title (plist-get info :title)))
                                                       (if title
                                                           (format "# %s\n\n%s" (car title) content)
                                                         content))))))
      "README.md"))
