package edu.fbansept.demo.contoller;

import edu.fbansept.demo.dao.UtilisateurDao;
import edu.fbansept.demo.model.Utilisateur;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.*;

import java.util.*;

@RestController
@CrossOrigin
public class UtilisateurController {

    @Autowired
    private UtilisateurDao utilisateurDao;

    @Autowired
    private PasswordEncoder passwordEncoder;

    @GetMapping("/admin/utilisateurs")
    public List<Utilisateur> getUtilisateursPourAdmin() {
        return utilisateurDao.findAll();
    }

    @GetMapping("/utilisateurs")
    public List<Utilisateur> getUtilisateursPourUtilisateur() {
        return utilisateurDao.findAll();
    }

}