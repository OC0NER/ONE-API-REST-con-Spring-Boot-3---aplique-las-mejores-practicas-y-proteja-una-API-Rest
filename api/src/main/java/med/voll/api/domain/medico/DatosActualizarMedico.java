package med.voll.api.domain.medico;

import jakarta.validation.constraints.NotNull;
import med.voll.api.DatosDireccion;

public record DatosActualizarMedico(
        @NotNull Long id,
        String nombre,
        String documento,
        DatosDireccion direccion
) {
}
